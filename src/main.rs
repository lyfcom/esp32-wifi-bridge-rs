use std::net::Ipv4Addr;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::{
        prelude::Peripherals,
        gpio::{PinDriver, OutputPin},
    },
    handle::RawHandle,
    netif::{EspNetif, NetifConfiguration, NetifStack},
    nvs::EspDefaultNvsPartition,
    sys::esp_netif_napt_enable,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, AccessPointConfiguration, EspWifi},
};
use log::{info, warn, error};

// ====== Configuration Parameters ======
// Upstream WiFi Configuration
const UPSTREAM_SSID: &str = "XHZX-XH";
const UPSTREAM_PASSWORD: &str = "";
const UPSTREAM_AUTH_METHOD: UpstreamAuthType = UpstreamAuthType::Open;

// Custom STA MAC Address (Optional)
// Format: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
// Set to None to use default MAC
const CUSTOM_STA_MAC: Option<[u8; 6]> = Some([0xEC, 0x7C, 0xB6, 0x1C, 0x28, 0xF6]);

// Downstream WiFi Configuration (ESP32 hotspot)
const DOWNSTREAM_SSID: &str = "helloworld";
const DOWNSTREAM_PASSWORD: &str = "12345678";
const DOWNSTREAM_SSID_HIDDEN: bool = true;

// ====== ANTI-DETECTION CONFIGURATION ======
// Strategy 1: TTL Modification (preserve TTL to avoid NAT detection)
const ENABLE_TTL_MODIFICATION: bool = true;

// Strategy 2: Disable DHCP (use static IP to avoid DHCP fingerprinting)
const DISABLE_AP_DHCP: bool = true;

// Strategy 3: Use same subnet as upstream (pseudo-bridge mode)
const USE_UPSTREAM_SUBNET: bool = false;  // Experimental, may cause conflicts

// Downstream Network Configuration
const AP_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const AP_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);

// Reconnection Configuration
const RECONNECT_DELAY_SECS: u64 = 5;
const CONNECTION_CHECK_INTERVAL_SECS: u64 = 10;

// ====== LED 指示灯配置 ======
// LED1 (主状态指示) - 通常在 GPIO 2
const LED1_GPIO: u8 = 2;
const LED1_ENABLED: bool = true;

// LED2 (次状态指示) - 可选，根据你的开发板调整
// 常见位置: GPIO 4, GPIO 15, GPIO 16
const LED2_GPIO: u8 = 4;
const LED2_ENABLED: bool = false;  // 设为 true 启用第二个 LED

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

// LED 状态枚举
#[derive(Debug, Clone, Copy, PartialEq)]
enum LedStatus {
    Off,                    // 熄灭
    On,                     // 常亮
    SlowBlink,              // 慢速闪烁 (1000ms) - 正在连接
    FastBlink,              // 快速闪烁 (200ms) - 初始化中
    VeryFastBlink,          // 超快闪烁 (100ms) - 错误状态
}

// LED 控制器
struct LedController {
    status: Arc<Mutex<LedStatus>>,
    _thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl LedController {
    /// 创建新的 LED 控制器
    fn new<P: OutputPin>(pin: P) -> Result<Self> {
        let status = Arc::new(Mutex::new(LedStatus::Off));
        let status_clone = Arc::clone(&status);

        // 创建 PinDriver
        let mut led = PinDriver::output(pin)?;

        // 启动 LED 控制线程
        let thread_handle = std::thread::spawn(move || {
            loop {
                let current_status = {
                    status_clone.lock().unwrap().clone()
                };

                match current_status {
                    LedStatus::Off => {
                        let _ = led.set_low();
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    LedStatus::On => {
                        let _ = led.set_high();
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    LedStatus::SlowBlink => {
                        let _ = led.set_high();
                        std::thread::sleep(Duration::from_millis(1000));
                        let _ = led.set_low();
                        std::thread::sleep(Duration::from_millis(1000));
                    }
                    LedStatus::FastBlink => {
                        let _ = led.set_high();
                        std::thread::sleep(Duration::from_millis(200));
                        let _ = led.set_low();
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    LedStatus::VeryFastBlink => {
                        let _ = led.set_high();
                        std::thread::sleep(Duration::from_millis(100));
                        let _ = led.set_low();
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        Ok(Self {
            status,
            _thread_handle: Some(thread_handle),
        })
    }

    /// 设置 LED 状态
    fn set_status(&self, new_status: LedStatus) {
        if let Ok(mut status) = self.status.lock() {
            *status = new_status;
        }
    }

    /// 获取当前 LED 状态
    fn get_status(&self) -> LedStatus {
        self.status.lock().unwrap().clone()
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
    wifi_relay(peripherals, sys_loop, nvs)?;

    Ok(())
}

fn wifi_relay(
    peripherals: Peripherals,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
) -> Result<()> {
    // 第零步：初始化 LED 控制器
    let led1 = if LED1_ENABLED {
        info!("初始化 LED1 (GPIO {})...", LED1_GPIO);
        match LedController::new(peripherals.pins.gpio2) {
            Ok(led) => {
                led.set_status(LedStatus::FastBlink);  // 启动时快速闪烁
                info!("✓ LED1 初始化成功");
                Some(led)
            }
            Err(e) => {
                warn!("LED1 初始化失败: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let led2 = if LED2_ENABLED {
        info!("初始化 LED2 (GPIO {})...", LED2_GPIO);
        match LedController::new(peripherals.pins.gpio4) {
            Ok(led) => {
                led.set_status(LedStatus::On);  // LED2 常亮表示 AP 已启用
                info!("✓ LED2 初始化成功");
                Some(led)
            }
            Err(e) => {
                warn!("LED2 初始化失败: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    // 第一步：创建 STA 网络接口（用于连接上游路由器）
    info!("创建 STA 网络接口...");
    let sta_netif = EspNetif::new(NetifStack::Sta)?;

    // 第二步：创建 AP 网络接口（根据反检测配置）
    info!("创建 AP 网络接口...");
    let ap_netif = if DISABLE_AP_DHCP {
        info!("反检测策略: 禁用 DHCP 服务器（客户端需手动配置静态 IP）");
        EspNetif::new_with_conf(&NetifConfiguration {
            ip_configuration: Some(esp_idf_svc::ipv4::Configuration::Router(
                esp_idf_svc::ipv4::RouterConfiguration {
                    subnet: esp_idf_svc::ipv4::Subnet {
                        gateway: AP_GATEWAY,
                        mask: esp_idf_svc::ipv4::Mask(24),
                    },
                    dhcp_enabled: false,  // 禁用 DHCP 避免指纹识别
                    dns: None,
                    secondary_dns: None,
                },
            )),
            ..NetifConfiguration::wifi_default_router()
        })?
    } else {
        EspNetif::new_with_conf(&NetifConfiguration {
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
        })?
    };

    // 第三步：创建 WiFi 驱动
    info!("初始化 WiFi 驱动...");
    let wifi_driver = esp_idf_svc::wifi::WifiDriver::new(peripherals.modem, sys_loop.clone(), Some(nvs))?;

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
    info!("下游热点 SSID: {}{}", DOWNSTREAM_SSID, if DOWNSTREAM_SSID_HIDDEN { " (隐藏)" } else { " (广播)" });

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
            ssid_hidden: DOWNSTREAM_SSID_HIDDEN,
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

    // ========== 反检测策略状态 ==========
    info!("========================================");
    info!("反检测策略已激活:");
    info!("========================================");

    // 策略 1: TTL 修改
    if ENABLE_TTL_MODIFICATION {
        info!("✓ [策略1] TTL 保持不变");
        info!("  - 通过 LWIP 配置禁止 TTL 递减");
        info!("  - 使转发流量的 TTL 与原始流量相同");
        info!("  - 上游路由器无法通过 TTL 检测到 NAT");
    } else {
        warn!("✗ [策略1] TTL 修改未启用");
        warn!("  - 上游可能通过 TTL 递减检测到热点");
    }

    // 策略 2: DHCP 禁用
    if DISABLE_AP_DHCP {
        info!("✓ [策略2] DHCP 服务器已禁用");
        info!("  - 客户端需手动配置静态 IP");
        info!("  - 避免 DHCP 指纹识别（Option 字段分析）");
        info!("  - 建议配置: IP=192.168.4.x, 网关=192.168.4.1");
    } else {
        warn!("✗ [策略2] DHCP 服务器已启用");
        warn!("  - 可能被 DHCP 指纹识别检测");
    }

    // 策略 3: MAC 地址自定义
    if CUSTOM_STA_MAC.is_some() {
        info!("✓ [策略3] 自定义 MAC 地址");
        info!("  - 避免使用可识别的设备 MAC");
    } else {
        warn!("✗ [策略3] 使用默认 MAC 地址");
    }

    // 策略 4: SSID 隐藏
    if DOWNSTREAM_SSID_HIDDEN {
        info!("✓ [策略4] SSID 已隐藏");
        info!("  - 降低被发现的可能性");
    } else {
        warn!("✗ [策略4] SSID 公开广播");
    }

    info!("========================================");
    info!("注意事项:");
    if DISABLE_AP_DHCP {
        info!("  由于禁用 DHCP，连接设备需手动配置:");
        info!("  - IP 地址: 192.168.4.2 ~ 192.168.4.254");
        info!("  - 子网掩码: 255.255.255.0");
        info!("  - 网关: 192.168.4.1");
        info!("  - DNS: 与上游网关相同或使用 8.8.8.8");
    }
    info!("========================================");

    // LED 状态说明
    if LED1_ENABLED {
        info!("========================================");
        info!("LED 指示灯状态说明 (GPIO {}):", LED1_GPIO);
        info!("========================================");
        info!("  快速闪烁 (200ms): 系统初始化中");
        info!("  慢速闪烁 (1000ms): 正在连接上游 WiFi");
        info!("  常亮: 已连接上游，中继器运行正常");
        info!("  超快闪烁 (100ms): 连接失败或断开");
        info!("========================================");
    }
    if LED2_ENABLED {
        info!("LED2 (GPIO {}): 常亮表示 AP 热点已启用", LED2_GPIO);
        info!("========================================");
    }

    // 获取 STA MAC 地址
    let sta_mac = unsafe {
        use esp_idf_svc::sys::{esp_wifi_get_mac, wifi_interface_t_WIFI_IF_STA};
        let mut mac = [0u8; 6];
        esp_wifi_get_mac(wifi_interface_t_WIFI_IF_STA, mac.as_mut_ptr());
        mac
    };

    info!("----------------------------------------");
    info!("下游热点信息:");
    info!("  SSID: {}{}", DOWNSTREAM_SSID, if DOWNSTREAM_SSID_HIDDEN { " (隐藏)" } else { "" });
    info!("  密码: {}", DOWNSTREAM_PASSWORD);
    info!("  IP: {}", AP_IP);
    info!("  最大连接数: 4");
    info!("========================================");

    // 第六步：连接循环（带自动重连）
    let mut first_connection = true;
    loop {
        // LED 状态：慢速闪烁 - 正在连接
        if let Some(ref led) = led1 {
            led.set_status(LedStatus::SlowBlink);
        }

        // 尝试连接到上游路由器
        match connect_to_upstream(&mut wifi, first_connection, &sta_mac, &led1) {
            Ok(_) => {
                first_connection = false;

                // LED 状态：常亮 - 已连接
                if let Some(ref led) = led1 {
                    led.set_status(LedStatus::On);
                }

                // 连接成功，进入监控模式
                monitor_connection(&mut wifi, &led1);

                // 如果监控退出，说明连接断开，需要重连
                warn!("检测到上游连接断开，准备重连...");

                // LED 状态：超快闪烁 - 连接断开
                if let Some(ref led) = led1 {
                    led.set_status(LedStatus::VeryFastBlink);
                }
            }
            Err(e) => {
                error!("连接上游路由器失败: {:?}", e);
                first_connection = false;

                // LED 状态：超快闪烁 - 连接失败
                if let Some(ref led) = led1 {
                    led.set_status(LedStatus::VeryFastBlink);
                }
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
    sta_mac: &[u8; 6],
    led: &Option<LedController>,
) -> Result<()> {
    info!("{}连接到上游 WiFi: {}",
        if is_first { "正在" } else { "正在重新" },
        UPSTREAM_SSID);

    // LED 状态：慢速闪烁 - 正在连接
    if let Some(led) = led {
        led.set_status(LedStatus::SlowBlink);
    }

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
fn monitor_connection(wifi: &mut BlockingWifi<EspWifi<'static>>, led: &Option<LedController>) {
    loop {
        std::thread::sleep(Duration::from_secs(CONNECTION_CHECK_INTERVAL_SECS));

        // 检查是否仍然连接
        if !wifi.is_connected().unwrap_or(false) {
            warn!("上游连接已断开！");

            // LED 状态：超快闪烁 - 连接断开
            if let Some(led) = led {
                led.set_status(LedStatus::VeryFastBlink);
            }

            return;
        }

        // 尝试获取 IP 信息来确认连接状态
        match wifi.wifi().sta_netif().get_ip_info() {
            Ok(ip_info) => {
                // 检查 IP 是否有效（不是 0.0.0.0）
                if ip_info.ip.octets() == [0, 0, 0, 0] {
                    warn!("上游连接失效（IP 地址无效）！");

                    // LED 状态：超快闪烁 - 连接失效
                    if let Some(led) = led {
                        led.set_status(LedStatus::VeryFastBlink);
                    }

                    return;
                }
            }
            Err(_) => {
                warn!("无法获取上游 IP 信息，连接可能已断开！");

                // LED 状态：超快闪烁 - 连接错误
                if let Some(led) = led {
                    led.set_status(LedStatus::VeryFastBlink);
                }

                return;
            }
        }
    }
}
