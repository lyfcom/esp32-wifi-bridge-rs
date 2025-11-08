use std::net::Ipv4Addr;
use std::time::Duration;
use anyhow::Result;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::prelude::Peripherals,
    handle::RawHandle,
    netif::{EspNetif, NetifConfiguration, NetifStack},
    nvs::EspDefaultNvsPartition,
    sys::esp_netif_napt_enable,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, AccessPointConfiguration, EspWifi},
};
use log::{info, warn, error};

// ====== 配置参数 ======
// 上游 WiFi 配置（需要连接的路由器）
const UPSTREAM_SSID: &str = "XHZX-XH";  // 修改为你的上游路由器 SSID
const UPSTREAM_PASSWORD: &str = "";  // 修改为你的上游路由器密码（开放网络留空）
const UPSTREAM_AUTH_METHOD: UpstreamAuthType = UpstreamAuthType::Open;  // 认证方式

// 自定义 STA 模式的 MAC 地址（可选）
// 格式：[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
// 设置为 None 使用默认 MAC 地址
const CUSTOM_STA_MAC: Option<[u8; 6]> = Some([0xEC, 0x7C, 0xB6, 0x1C, 0x28, 0xF6]);

// 下游 WiFi 配置（ESP32 创建的热点）
const DOWNSTREAM_SSID: &str = "XHZX-临时";  // ESP32 热点名称
const DOWNSTREAM_PASSWORD: &str = "12345678";  // ESP32 热点密码（至少8位）

// 下游网络配置
const AP_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const AP_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);

// 重连配置
const RECONNECT_DELAY_SECS: u64 = 5;  // 重连延迟（秒）
const CONNECTION_CHECK_INTERVAL_SECS: u64 = 10;  // 连接状态检查间隔（秒）

// 上游认证类型
#[derive(Debug, Clone, Copy)]
enum UpstreamAuthType {
    Open,           // 开放网络（无密码）
    WPA2Personal,   // WPA2-PSK
    WPAWpa2Personal, // WPA/WPA2-PSK
}

impl UpstreamAuthType {
    fn to_auth_method(&self) -> AuthMethod {
        match self {
            UpstreamAuthType::Open => AuthMethod::None,
            UpstreamAuthType::WPA2Personal => AuthMethod::WPA2Personal,
            UpstreamAuthType::WPAWpa2Personal => AuthMethod::WPAWPA2Personal,
        }
    }

    fn description(&self) -> &str {
        match self {
            UpstreamAuthType::Open => "开放网络",
            UpstreamAuthType::WPA2Personal => "WPA2-PSK",
            UpstreamAuthType::WPAWpa2Personal => "WPA/WPA2-PSK",
        }
    }
}

fn main() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("========================================");
    info!("    ESP32 WiFi 中继器启动中...");
    info!("========================================");

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // 创建 WiFi 中继
    wifi_relay(peripherals.modem, sys_loop, nvs)?;

    Ok(())
}

fn wifi_relay(
    modem: impl esp_idf_svc::hal::peripheral::Peripheral<P = esp_idf_svc::hal::modem::Modem> + 'static,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
) -> Result<()> {
    // 第一步：创建 STA 网络接口（用于连接上游路由器）
    info!("创建 STA 网络接口...");
    let sta_netif = EspNetif::new(NetifStack::Sta)?;

    // 第二步：创建 AP 网络接口（用于创建下游热点）
    info!("创建 AP 网络接口...");
    let ap_netif = EspNetif::new_with_conf(&NetifConfiguration {
        ip_configuration: Some(esp_idf_svc::ipv4::Configuration::Router(
            esp_idf_svc::ipv4::RouterConfiguration {
                subnet: esp_idf_svc::ipv4::Subnet {
                    gateway: AP_GATEWAY,
                    mask: esp_idf_svc::ipv4::Mask(24),
                },
                dhcp_enabled: true,
                dns: None,
                secondary_dns: None,
            },
        )),
        ..NetifConfiguration::wifi_default_router()
    })?;

    // 第三步：创建 WiFi 驱动
    info!("初始化 WiFi 驱动...");
    let wifi_driver = esp_idf_svc::wifi::WifiDriver::new(modem, sys_loop.clone(), Some(nvs))?;

    // 第三步半：设置自定义 MAC 地址（如果配置了）
    if let Some(custom_mac) = CUSTOM_STA_MAC {
        info!("设置自定义 STA MAC 地址: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            custom_mac[0], custom_mac[1], custom_mac[2],
            custom_mac[3], custom_mac[4], custom_mac[5]);

        unsafe {
            use esp_idf_svc::sys::{esp_wifi_set_mac, wifi_interface_t_WIFI_IF_STA};
            let ret = esp_wifi_set_mac(
                wifi_interface_t_WIFI_IF_STA,
                custom_mac.as_ptr() as *const u8
            );
            if ret != 0 {
                warn!("警告: 设置 MAC 地址失败，错误码: {}", ret);
            } else {
                info!("✓ MAC 地址设置成功");
            }
        }
    } else {
        // 显示默认 MAC 地址
        unsafe {
            use esp_idf_svc::sys::{esp_wifi_get_mac, wifi_interface_t_WIFI_IF_STA};
            let mut mac = [0u8; 6];
            esp_wifi_get_mac(wifi_interface_t_WIFI_IF_STA, mac.as_mut_ptr());
            info!("使用默认 STA MAC 地址: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }

    let mut wifi = BlockingWifi::wrap(
        EspWifi::wrap_all(wifi_driver, sta_netif, ap_netif)?,
        sys_loop,
    )?;

    // 第四步：配置 WiFi（同时配置 STA 和 AP 模式）
    info!("配置 WiFi（APSTA 模式）...");
    info!("上游认证方式: {}", UPSTREAM_AUTH_METHOD.description());

    let auth_method = UPSTREAM_AUTH_METHOD.to_auth_method();

    wifi.set_configuration(&Configuration::Mixed(
        // STA 配置：连接上游路由器
        ClientConfiguration {
            ssid: UPSTREAM_SSID.try_into().unwrap(),
            password: UPSTREAM_PASSWORD.try_into().unwrap(),
            auth_method,
            ..Default::default()
        },
        // AP 配置：创建下游热点
        AccessPointConfiguration {
            ssid: DOWNSTREAM_SSID.try_into().unwrap(),
            password: DOWNSTREAM_PASSWORD.try_into().unwrap(),
            auth_method: AuthMethod::WPA2Personal,
            max_connections: 4,
            ..Default::default()
        },
    ))?;

    // 第五步：启动 WiFi
    info!("启动 WiFi...");
    wifi.start()?;

    // 启用 NAT（只需设置一次）
    info!("启用 NAT 转发...");
    unsafe {
        let ap_netif_handle = wifi.wifi().ap_netif().handle();
        esp_netif_napt_enable(ap_netif_handle);
    }
    info!("✓ NAT 已启用！");

    // 获取 STA MAC 地址
    let sta_mac = unsafe {
        use esp_idf_svc::sys::{esp_wifi_get_mac, wifi_interface_t_WIFI_IF_STA};
        let mut mac = [0u8; 6];
        esp_wifi_get_mac(wifi_interface_t_WIFI_IF_STA, mac.as_mut_ptr());
        mac
    };

    info!("----------------------------------------");
    info!("下游热点信息:");
    info!("  SSID: {}", DOWNSTREAM_SSID);
    info!("  密码: {}", DOWNSTREAM_PASSWORD);
    info!("  IP: {}", AP_IP);
    info!("  最大连接数: 4");
    info!("========================================");

    // 第六步：连接循环（带自动重连）
    let mut first_connection = true;
    loop {
        // 尝试连接到上游路由器
        match connect_to_upstream(&mut wifi, first_connection, &sta_mac) {
            Ok(_) => {
                first_connection = false;
                // 连接成功，进入监控模式
                monitor_connection(&mut wifi);
                // 如果监控退出，说明连接断开，需要重连
                warn!("检测到上游连接断开，准备重连...");
            }
            Err(e) => {
                error!("连接上游路由器失败: {:?}", e);
                first_connection = false;
            }
        }

        // 等待一段时间后重连
        info!("等待 {} 秒后重试连接...", RECONNECT_DELAY_SECS);
        std::thread::sleep(Duration::from_secs(RECONNECT_DELAY_SECS));
    }
}

/// 连接到上游路由器
fn connect_to_upstream(
    wifi: &mut BlockingWifi<EspWifi<'static>>,
    is_first: bool,
    sta_mac: &[u8; 6]
) -> Result<()> {
    info!("{}连接到上游 WiFi: {}",
        if is_first { "正在" } else { "正在重新" },
        UPSTREAM_SSID);

    // 尝试连接
    wifi.connect()?;
    info!("等待获取 IP 地址...");
    wifi.wait_netif_up()?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;

    info!("========================================");
    info!("✓ {}连接到上游路由器成功！", if is_first { "已" } else { "重新" });
    info!("----------------------------------------");
    info!("上游连接信息:");
    info!("  SSID: {}", UPSTREAM_SSID);
    info!("  认证: {}", UPSTREAM_AUTH_METHOD.description());
    info!("  IP: {}", ip_info.ip);
    info!("  网关: {}", ip_info.subnet.gateway);
    info!("  子网掩码: {}", ip_info.subnet.mask);
    info!("  MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
    info!("========================================");
    info!("WiFi 中继器运行中，设备可以连接到 ESP32 热点访问互联网");

    Ok(())
}

/// 监控连接状态
fn monitor_connection(wifi: &mut BlockingWifi<EspWifi<'static>>) {
    loop {
        std::thread::sleep(Duration::from_secs(CONNECTION_CHECK_INTERVAL_SECS));

        // 检查是否仍然连接
        if !wifi.is_connected().unwrap_or(false) {
            warn!("上游连接已断开！");
            return;
        }

        // 尝试获取 IP 信息来确认连接状态
        match wifi.wifi().sta_netif().get_ip_info() {
            Ok(ip_info) => {
                // 检查 IP 是否有效（不是 0.0.0.0）
                if ip_info.ip.octets() == [0, 0, 0, 0] {
                    warn!("上游连接失效（IP 地址无效）！");
                    return;
                }
            }
            Err(_) => {
                warn!("无法获取上游 IP 信息，连接可能已断开！");
                return;
            }
        }
    }
}
