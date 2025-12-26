/*
 * Touch Input Mapper Driver - 键鼠转触摸映射驱动 (隐藏增强版V4.2 FINAL)
 * 核心特性：开机读配置 + 内置boot兼容 + 用户态修改配置+触发重载 + 真人触摸模拟 + Proc隐藏 + 动态加载+内存隐藏
 * 兼容：Android 6.1 GKI 内核 / Linux 5.10-6.0
 * 配置文件：/data/smw.bin（root可读写）
 * 注意：请勿修改 stealth_input_event 函数的返回值
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/input/mt.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/math64.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/math.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/random.h>
// 新增：内核版本判断宏（适配 6.1+ API 变化）
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#define PROC_FIND_ENTRY_RET_INT 1  // 6.1+ 内核：proc_find_entry 返回 int
#else
#define PROC_FIND_ENTRY_RET_INT 0  // 旧内核：返回指针
#endif
#include <linux/proc_fs.h>
// 补充6.1+内核proc接口兼容
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
#define proc_lookup proc_find_entry
#endif
#include <linux/fs_struct.h>
#include <linux/pid_namespace.h>
// 配置监控依赖头文件
#include <linux/file.h>
// 内核版本兼容宏（补充低版本适配）
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#ifndef msecs_to_jiffies
#define msecs_to_jiffies(x) ((x) * HZ / 1000)
#endif
#define MY_LINUX_VERSION_CODE LINUX_VERSION_CODE
// GKI内核兼容配置（移除MODULE_FLAGS）
#ifdef CONFIG_GKI_COMPAT
#define GKI_MODULE_FLAGS MODULE_INIT_IGNORE_MODVERSIONS
#else
#define GKI_MODULE_FLAGS 0
#endif
extern void *kallsyms_lookup_name(const char *name);
#define HAVE_CRYPTO_ALLOC_HASH 1 // 强制启用你写的动态查找逻辑
#ifndef HAVE_CRYPTO_ALLOC_HASH
// 动态查找 crypto_alloc_shash（适配6.1+内核，原功能不变）
static struct crypto_shash *(*my_crypto_alloc_shash)(const char *alg_name, u32 type, u32 mask) = NULL;
static void (*my_crypto_free_shash)(struct crypto_shash *tfm) = NULL;
static int find_crypto_symbols(void);
static inline struct crypto_shash *safe_crypto_alloc_shash(const char *alg_name, u32 type, u32 mask);
static inline void safe_crypto_free_shash(struct crypto_shash *tfm);
static int find_crypto_symbols(void)
{
    // 尝试查找 shash 接口（6.1+内核推荐）
    my_crypto_alloc_shash = (void *)kallsyms_lookup_name("crypto_alloc_shash");
    my_crypto_free_shash = (void *)kallsyms_lookup_name("crypto_free_shash");
    
    if (my_crypto_alloc_shash && my_crypto_free_shash) {
        log_info("Found crypto_shash interface\n");
        return 0;
    }
    
    // 未找到则提示错误
    printk(KERN_ERR "crypto_alloc_shash/crypto_free_shash not found\n");
    return -ENOENT;
}

// 包装函数（不改变调用逻辑，适配shash）
static inline struct crypto_shash *safe_crypto_alloc_shash(const char *alg_name, u32 type, u32 mask)
{
    if (my_crypto_alloc_shash)
        return my_crypto_alloc_shash(alg_name, type, mask);
    return ERR_PTR(-ENOSYS);
}

static inline void safe_crypto_free_shash(struct crypto_shash *tfm)
{
    if (my_crypto_free_shash && tfm && !IS_ERR(tfm))
        my_crypto_free_shash(tfm);
}

#endif

// 调试开关（强制关闭，增强隐蔽性）
#define DEBUG_MODE 0
#if DEBUG_MODE
#define log_info(...) printk(KERN_INFO "[Touch-Mapper] " __VA_ARGS__)
#else
#define log_info(...) do {} while(0)
#endif
// 反检测核心配置
#define HIDE_PROC_NAME "touch_mapper"
#define COMM_AUTH_KEY "c2a2b5792edd296763fdfc72cff44380" // 32字节密钥（保留加密通信）
#define KEY_LEN 32
#define XOR_ENCRYPT_KEY 0x9D
#define MD5_DIGEST_LEN 16
// 视角配置常量
#define VIEW_IDLE_TIMEOUT_MS 500
#define VIEW_RESET_JITTER 15
// 命令缓冲区大小定义
#define MAX_CMD_LEN 256
#define MAX_ENCRYPTED_LEN (MAX_CMD_LEN + MD5_DIGEST_LEN)
#define MAX_COMBINED_LEN (MAX_CMD_LEN + KEY_LEN)
#define MAX_DECRYPTED_LEN MAX_CMD_LEN
// 真人触摸动态参数
struct real_touch_params {
    int jitter_range;
    int slide_accel; // 整数缩放：100=1.0，120=1.2
    int slide_decel; // 80=0.8
    int pressure_min;
    int pressure_max;
    int click_delay_range;
};
static struct real_touch_params g_real_touch_params = {
    .jitter_range = 8, //按键随机落点调整
    .slide_accel = 120,
    .slide_decel = 80,
    .pressure_min = 80,
    .pressure_max = 200,
    .click_delay_range = 20,
};
// 动作类型定义
#define ACTION_CLICK              0
#define ACTION_HOLD               1
#define ACTION_FOLLOW_KEYBOARD    3
// 内核参数（支持配置文件覆盖）
static int screen_width = 3000;
static int screen_height = 2120;
static int view_center_x = -1;
static int view_center_y = -1;
static int view_max_radius = 0;
static int view_deadzone = 10;
static int view_sensitivity = 100;
// 配置文件路径（固定为/data/smw.bin）
static char config_save_path[256] = "/data/smw.bin";
// 驱动/设备/类名称（深度伪装，系统原生风格）
#define DRIVER_NAME "input_hid_compat"
#define DEVICE_NAME "hid_compat"
#define CLASS_NAME "input"
#define INPUT_NAME "HID Compatible Touch Device"
// 基础定义
#define MAGIC_SIGNATURE 0x51444953
#define CMD_CHANNEL_NUM 5
#define CMD_HEAD_LEN 1
#define CMD_DIGEST_LEN MD5_DIGEST_LEN
// 命令类型（含CMD_RELOAD_CONFIG）
#define CMD_START_KEY_LEARN        0xAD
#define CMD_STOP_KEY_LEARN         0xAE
#define CMD_SET_LEARN_PARAM        0xAF
#define CMD_SAVE_CONFIG            0xAB
#define CMD_SET_REAL_TOUCH_PARAM   0x10
#define CMD_GET_REAL_TOUCH_PARAM   0x11
#define CMD_SET_VIEW_AREA          0x12
#define CMD_ADD_KEY_MAPPING    0x15 // 添加按键映射
#define CMD_DEL_KEY_MAPPING    0x16 // 删除按键映射
#define CMD_SET_JOYSTICK_PARAM   0x13 // 设置轮盘参数（新增）
#define CMD_GET_JOYSTICK_PARAM   0x14 // 获取轮盘参数（新增）
#define CMD_RELOAD_CONFIG          0xAC // 重新加载配置文件
// 模式定义
#define MODE_VIEW           1
#define MODE_SILENT         3
#define SLIDE_FOLLOW_MOUSE  2
// 配置序列化结构体
struct config_header {
    unsigned int magic;
    unsigned int version;
};
struct key_map_serialize {
    int keycode;
    int action;
    int x;
    int y;
    int duration;
    int instant_release;
    int jitter;
};
struct view_area_serialize {
    int center_x;
    int center_y;
    int max_radius;
    int deadzone;
    int sensitivity;
};
// 轮盘配置序列化结构体（新增）
struct joystick_serialize {
    int center_x;
    int center_y;
    int radius;
    int deadzone;
    int jitter_range;
    int key_up;
    int key_down;
    int key_left;
    int key_right;
};

// 全局配置序列化（新增轮盘配置）
struct global_config_serialize {
    int jitter_range;
    int current_mode;
    struct view_area_serialize view_area;
    struct joystick_serialize joystick; // ✅ 加入轮盘配置
};

// 按键映射结构体
struct key_mapping {
    int keycode;
    char key_name[32];
    int action;
    int instant_release;
    int slot;
    int jitter;
    union {
        struct { int x; int y; int duration; } click;
        struct { int x; int y; int pressure; } hold;
    } params;
    struct key_mapping *next;
};
// 真人触摸状态结构体
struct real_touch_state {
    int last_dx;
    int last_dy;
    unsigned long last_time;
    int pressure_offset;
};
// 核心配置结构体
struct stealth_config {
    int activated; // ✅ 改为运行时初始化，加载驱动即生效
    unsigned long activate_time;
    int key_learn_active;
    int learned_keycode;
    int learn_timeout;
    int screen_width;
    int screen_height;
    int max_touch_points;
    struct {
    int enabled;
    int trigger_key;
    int mode; // 0=固定方向，2=跟随鼠标（对应 SLIDE_FOLLOW_MOUSE）
    int max_radius;
    int sensitivity;
    int active;
    int current_x;
    int current_y;
    int slide_x;
    int slide_y;
    struct real_touch_state touch_state;
} slide_key;

    struct {
        int speed;
        int current_x;
        int current_y;
        int visible;
    } cursor;
    struct {
        int center_x;
        int center_y;
        int max_radius;
        int deadzone;
        int sensitivity;
        int active;
        int current_x;
        int current_y;
        struct real_touch_state touch_state;
        unsigned long last_move_time;
        bool touch_held;
        bool edge_reset_flag;
        int jitter_range;
    } view;
    struct {
    int enabled;
    int center_x;
    int center_y;
    int radius;
    int deadzone;
    int active;
    int current_x;
    int current_y;
    int move_slot;
    int key_up;
    int key_down;
    int key_left;
    int key_right;
    unsigned long key_states;
    int jitter_range;
    int press_jitter_range; // 新增：轮盘按压持续抖动专属参数
    struct real_touch_state touch_state;
} joystick;

    struct key_mapping *keymap_list;
    int keymap_count;
    int current_mode;
    int enable_instant_release;
    unsigned long stats_moves;
    unsigned long stats_clicks;
    unsigned long stats_commands;
    unsigned long stats_learned_keys;
};
// 设备结构体（唯一定义，已修复所有问题）
struct stealth_device {
    struct input_dev *input_dev;
    struct cdev cdev;
    dev_t devno;
    struct class *class;
    struct device *device;
    struct stealth_config config;
    struct mutex lock;
    spinlock_t config_lock;
    wait_queue_head_t cmd_waitq;
    struct {
        unsigned char data[256];
        int len;
        int channel;
        unsigned int magic;
    } cmd_channels[CMD_CHANNEL_NUM];
    struct timer_list learn_timeout_timer;
    struct timer_list view_idle_timer;
    unsigned char hidden_id[16];
    struct workqueue_struct *workqueue;
    struct work_struct input_work;
    struct work_struct learn_timeout_work;
    struct work_struct view_idle_work;
    struct work_struct view_reset_work;
    struct { int type; int code; int value; } input_buffer[32];
    int buffer_head;
    int buffer_tail;
    struct crypto_shash *md5_tfm; // 适配GKI的加密算法句柄（替换shash为hash）
    struct real_touch_state default_touch_state; // ✅ 已添加：修复未声明问题
};

static struct stealth_device *stealth_dev;
// 配置文件监控结构体
static struct file_monitor {
    struct delayed_work monitor_work;
    unsigned long last_mtime;  // 记录上次文件修改时间
} config_monitor;
// Proc隐藏相关全局变量
static struct proc_dir_entry *hide_proc_dir;
// 函数名混淆宏
#define _HIDE(x) x##_hide
#define hide_func(x) _HIDE(x)
// 提前声明所有函数（修复遗漏声明）

extern const struct attribute_group stealth_attr_group;
static void hide_func(handle_key_binding)(int keycode, int value);
static void hide_func(update_joystick_state)(int keycode, int value);
static void hide_func(process_learned_key)(int code);
static void hide_func(send_real_touch_event)(int slot, int x, int y, int pressure, struct real_touch_state *state, int center_x, int center_y);
static void hide_func(handle_view_move)(int dx, int dy);
static int hide_func(real_touch_get_pressure)(struct real_touch_state *state);
static void hide_func(real_touch_add_jitter)(int *x, int *y);
static struct key_mapping *hide_func(find_key_mapping)(int keycode);
static void hide_func(start_key_learn)(struct stealth_config *cfg);
static void hide_func(stop_key_learn)(struct stealth_config *cfg);
static int hide_func(save_stealth_config)(void);
static int hide_func(load_stealth_config)(void);
static void hide_func(init_default_keymap)(struct stealth_config *cfg);
static void hide_func(detect_screen_resolution)(struct stealth_config *cfg);
static void hide_func(init_view_area)(struct stealth_config *cfg);
static const char *hide_func(key_name)(int keycode);
static void hide_func(generate_hidden_id)(unsigned char *id, int len);
static void hide_func(learn_timeout_work_func)(struct work_struct *work);
static void hide_func(view_idle_work_func)(struct work_struct *work);
static void hide_func(view_reset_work_func)(struct work_struct *work);
static int hide_func(md5_hash)(const unsigned char *data, size_t len, unsigned char *digest);
static void hide_func(xor_encrypt)(unsigned char *data, size_t len);
static int hide_func(verify_command)(unsigned char *data, size_t len, unsigned char *cmd_out, size_t *cmd_len_out);

static ssize_t hide_func(proc_read)(struct file *file, char __user *buf, size_t count, loff_t *pos);
static int hide_func(proc_open)(struct inode *inode, struct file *file);
static bool hide_func(init_proc_hide)(void);
static void hide_func(exit_proc_hide)(void);
static void hide_func(real_touch_add_angle_offset)(int *x, int *y, int center_x, int center_y);
static void hide_func(handle_slide_key)(int dx, int dy);
static long hide_func(stealth_ioctl)(struct file *filp, unsigned int cmd, unsigned long arg);
static int hide_func(stealth_open)(struct inode *inode, struct file *filp);
static int hide_func(stealth_release)(struct inode *inode, struct file *filp);
static void hide_func(stealth_input_event)(struct input_handle *handle, unsigned int type, unsigned int code, int value);
static void hide_func(stealth_input_disconnect)(struct input_handle *handle);
static int hide_func(stealth_input_connect)(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id);
static int hide_func(reload_smw_config)(void);
static void hide_func(config_monitor_workfn)(struct work_struct *work);
static const struct file_operations hide_proc_fops;
// 输入设备ID表
static const struct input_device_id stealth_input_ids[] = {
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
        .evbit = { BIT_MASK(EV_KEY) },
        .keybit = { [BIT_WORD(KEY_A)] = BIT_MASK(KEY_A) },
    },
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_RELBIT,
        .evbit = { BIT_MASK(EV_REL) },
        .relbit = { [BIT_WORD(REL_X)] = BIT_MASK(REL_X) },
    },
    { },
};
MODULE_DEVICE_TABLE(input, stealth_input_ids);
// GKI内核兼容：输入处理器定义
static struct input_handler stealth_input_handler = {
    .name = DRIVER_NAME,
    .id_table = stealth_input_ids,
    .event = hide_func(stealth_input_event),
    .connect = hide_func(stealth_input_connect),
    .disconnect = hide_func(stealth_input_disconnect),
};
// 输入工作队列处理函数
static void hide_func(input_work_func)(struct work_struct *work) {
    struct stealth_device *dev = container_of(work, struct stealth_device, input_work);
    unsigned long flags;
    int type, code, value;
    
    if (!dev) return; // 空指针检查
    
    spin_lock_irqsave(&dev->config_lock, flags);
    while (dev->buffer_head != dev->buffer_tail) {
        type = dev->input_buffer[dev->buffer_tail].type;
        code = dev->input_buffer[dev->buffer_tail].code;
        value = dev->input_buffer[dev->buffer_tail].value;
        dev->buffer_tail = (dev->buffer_tail + 1) % ARRAY_SIZE(dev->input_buffer);
        spin_unlock_irqrestore(&dev->config_lock, flags);
        
        switch (type) {
            case EV_KEY:
                if (dev->config.key_learn_active) {
                    if (value == 1) {
                        hide_func(process_learned_key)(code);
                    }
                } else {
                    hide_func(handle_key_binding)(code, value);
                    hide_func(update_joystick_state)(code, value);
                }
                break;
            case EV_REL:
                if (code == REL_X || code == REL_Y) {
                    static int rel_x_accum = 0, rel_y_accum = 0;
                    if (code == REL_X) rel_x_accum += value;
                    if (code == REL_Y) rel_y_accum += value;
                    if (abs(rel_x_accum) >= 5 || abs(rel_y_accum) >= 5) {
                        hide_func(handle_view_move)(rel_x_accum, rel_y_accum);
                        rel_x_accum = 0;
                        rel_y_accum = 0;
                    }
                }
                break;
            default:
                break;
        }
        
        spin_lock_irqsave(&dev->config_lock, flags);
    }
    spin_unlock_irqrestore(&dev->config_lock, flags);
}
// 加密核心（保留，用于命令校验）
static int hide_func(md5_hash)(const unsigned char *data, size_t len, unsigned char *digest) {
    struct shash_desc *desc; // ✅ 还原为shash_desc
    int ret;
    
    if (!stealth_dev || !stealth_dev->md5_tfm) return -ENOMEM;
    
    // 分配shash描述符（原hash_desc无需分配，shash需要）
    desc = kzalloc(sizeof(*desc), GFP_KERNEL);
    if (!desc) return -ENOMEM;
    desc->tfm = (struct crypto_shash *)stealth_dev->md5_tfm; // ✅ 类型转换
    
    unsigned char combined[MAX_COMBINED_LEN];
    if (len + KEY_LEN > MAX_COMBINED_LEN) {
        ret = -EINVAL;
        goto free_desc;
    }
    memcpy(combined, data, len);
    memcpy(combined + len, COMM_AUTH_KEY, KEY_LEN);
    
    // ✅ 还原为crypto_shash_digest（6.1内核支持）
    ret = crypto_shash_digest(desc, combined, len + KEY_LEN, digest);
    
free_desc:
    kfree(desc); // 释放描述符
    return ret;
}

static void hide_func(xor_encrypt)(unsigned char *data, size_t len) {
    const unsigned char key = XOR_ENCRYPT_KEY;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
static int hide_func(verify_command)(unsigned char *data, size_t len, unsigned char *cmd_out, size_t *cmd_len_out) {
    if (len < CMD_DIGEST_LEN) return -EINVAL;
    
    size_t data_len = len - CMD_DIGEST_LEN;
    unsigned char received_digest[CMD_DIGEST_LEN];
    unsigned char calc_digest[CMD_DIGEST_LEN];
    unsigned char decrypted[MAX_DECRYPTED_LEN];
    
    if (data_len > MAX_DECRYPTED_LEN) return -EINVAL;
    
    memcpy(received_digest, data + data_len, CMD_DIGEST_LEN);
    memcpy(decrypted, data, data_len);
    
    hide_func(xor_encrypt)(decrypted, data_len);
    
    if (hide_func(md5_hash)(decrypted, data_len, calc_digest) != 0) {
        return -EINVAL;
    }
    
    if (memcmp(calc_digest, received_digest, CMD_DIGEST_LEN) != 0) {
        log_info("Command auth failed\n");
        return -EACCES;
    }
    
    memcpy(cmd_out, decrypted, data_len);
    *cmd_len_out = data_len;
    return 0;
}
// 反检测核心：Proc隐藏 + 模块痕迹清理
// 合规的Proc隐藏实现（适配6.1+内核）
static ssize_t hide_func(proc_read)(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    return 0; // 空实现，避免工具读取到内容
}

static int hide_func(proc_open)(struct inode *inode, struct file *file) {
    return single_open(file, NULL, NULL); // ✅ 直接传NULL，无需PDE_DATA
}


// Proc操作集合（适配6.1+内核proc_ops接口，替换旧的file_operations）
static const struct proc_ops hide_proc_ops = {
    .proc_open = hide_func(proc_open),  // 对应打开操作
    .proc_read = hide_func(proc_read),  // 对应读取操作
    .proc_lseek = seq_lseek,           // 保留原有逻辑
    .proc_release = single_release,    // 保留原有逻辑
};

// 新的Proc隐藏初始化
static bool hide_func(init_proc_hide)(void) {
    // 创建隐藏的Proc条目，用合规接口
    hide_proc_dir = proc_create_data(HIDE_PROC_NAME, 0644, NULL, &hide_proc_ops, NULL); // ✅ 改用proc_ops
    if (!hide_proc_dir) {
        log_info("Proc hide init failed\n");
        return false;
    }
    log_info("Proc hide initialized (合规版)\n");
    return true;
}
// 新的Proc隐藏清理
static void hide_func(exit_proc_hide)(void) {
    if (hide_proc_dir) {
        proc_remove(hide_proc_dir); // 合规删除Proc条目
        hide_proc_dir = NULL;
    }
    log_info("Proc hide exited\n");
}
// 替代原clean_module_trace：新手友好版痕迹清理（无未导出符号）
static void hide_func(stealth_clean_trace)(void) {
    struct module *mod = THIS_MODULE;

    // 1. 清空模块名称（lsmod看不到）
    mod->name[0] = '\0';
    mod->args = NULL;
    module_put(mod);

    // 2. 清理sysfs痕迹（隐藏设备属性）
    if (stealth_dev && stealth_dev->device) {
        sysfs_remove_group(&stealth_dev->device->kobj, &stealth_attr_group);
        kobject_del(&stealth_dev->device->kobj);
    }

    // 3. 清理proc痕迹
    hide_func(exit_proc_hide)();

    // 4. 覆盖驱动关键词（避免游戏扫描）
    memset(DRIVER_NAME, 0, sizeof(DRIVER_NAME));
    memset(DEVICE_NAME, 0, sizeof(DEVICE_NAME));
    memset(INPUT_NAME, 0, sizeof(INPUT_NAME));

    pr_info("痕迹清理完成\n");
}

// 隐藏内存特征（避免游戏扫描驱动关键词）
static void hide_func(stealth_hide_mem_signature)(void) {
    char *keywords[] = {"touch_mapper", "stealth", "key_mapping", "joystick"};
    for (int i = 0; i < ARRAY_SIZE(keywords); i++) {
        char *addr = (char *)kallsyms_lookup_name(keywords[i]);
        if (addr) memset(addr, 0x00, strlen(keywords[i]));
    }
}

// 真人触摸模拟核心函数
static int hide_func(real_touch_get_pressure)(struct real_touch_state *state) {
    if (!state) return g_real_touch_params.pressure_min;
    
    unsigned int rand_val;
    get_random_bytes(&rand_val, sizeof(rand_val));
    state->pressure_offset = (rand_val % 30) - 15;;
    
    int pressure = g_real_touch_params.pressure_min + (rand_val % (g_real_touch_params.pressure_max - g_real_touch_params.pressure_min));
    pressure += state->pressure_offset;
    return clamp_val(pressure, g_real_touch_params.pressure_min, g_real_touch_params.pressure_max);
}
static void hide_func(real_touch_add_jitter)(int *x, int *y) {
    unsigned int rand_val;
    get_random_bytes(&rand_val, sizeof(rand_val));
    
    int jx = (rand_val % (g_real_touch_params.jitter_range * 2 + 1)) - g_real_touch_params.jitter_range;
    int jy = ((rand_val >> 8) % (g_real_touch_params.jitter_range * 2 + 1)) - g_real_touch_params.jitter_range;
    
    *x += jx;
    *y += jy;
}
static void hide_func(real_touch_add_angle_offset)(int *x, int *y, int center_x, int center_y) {
    unsigned int rand_val;
    get_random_bytes(&rand_val, sizeof(rand_val));
    
    int angle_deg = (rand_val % 10) - 5;
    int dx = *x - center_x;
    int dy = *y - center_y;
    
    int angle_rad_scaled = angle_deg * 1000;
    int new_dx = dx - (dy * angle_rad_scaled) / 1000;
    int new_dy = dy + (dx * angle_rad_scaled) / 1000;
    
    *x = center_x + new_dx;
    *y = center_y + new_dy;
}
static void hide_func(send_real_touch_event)(int slot, int x, int y, int pressure, struct real_touch_state *state, int center_x, int center_y) {
    struct input_dev *dev = stealth_dev ? stealth_dev->input_dev : NULL;
    if (!dev || !stealth_dev->config.activated) return;
    if (stealth_dev->config.current_mode == MODE_SILENT) return;
    
    x = clamp_val(x, 0, stealth_dev->config.screen_width - 1);
    y = clamp_val(y, 0, stealth_dev->config.screen_height - 1);
    
    // 轮盘按压时使用专属持续抖动（已添加压力动态关联），其他功能用全局抖动
    if (slot == stealth_dev->config.joystick.move_slot && stealth_dev->config.joystick.press_jitter_range > 0) {
        // 核心优化：根据压力值动态调整抖动幅度（压力越大，抖动略小，贴近真人）
        int pressure_factor = pressure > 0 ? (255 - pressure) / 30 : 0; // 压力映射为0~8的调整系数
        int dynamic_jitter = stealth_dev->config.joystick.press_jitter_range + pressure_factor; // 动态抖动范围（±11~±19）
        
        // 轮盘专属持续抖动（动态调整后）
        unsigned int rand_val;
        get_random_bytes(&rand_val, sizeof(rand_val));
        int jx = (rand_val % (dynamic_jitter * 2 + 1)) - dynamic_jitter;
        int jy = ((rand_val >> 8) % (dynamic_jitter * 2 + 1)) - dynamic_jitter;
        x += jx;
        y += jy;
        msleep(25);
        // 叠加角度偏移，抖动更自然
        if (center_x >=0 && center_y >=0) {
            hide_func(real_touch_add_angle_offset)(&x, &y, center_x, center_y);
        }
    } else {
        // 其他功能（视角、普通按键）：保留原有全局抖动
        hide_func(real_touch_add_jitter)(&x, &y);
        if (center_x >=0 && center_y >=0) {
            hide_func(real_touch_add_angle_offset)(&x, &y, center_x, center_y);
        }
        msleep(28);
    }
    
    if (pressure > 0) {
        pressure = hide_func(real_touch_get_pressure)(state);
        int touch_major = 5 + (pressure % 12);
        input_report_abs(dev, ABS_MT_TOUCH_MAJOR, touch_major);
    } else {
        pressure = 0;
        input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 0);
    }
    
    input_mt_slot(dev, slot);
    input_mt_report_slot_state(dev, MT_TOOL_FINGER, pressure > 0);
    
    if (pressure > 0) {
        input_report_abs(dev, ABS_MT_POSITION_X, x);
        input_report_abs(dev, ABS_MT_POSITION_Y, y);
        input_report_abs(dev, ABS_MT_PRESSURE, pressure);
        input_report_abs(dev, ABS_MT_TRACKING_ID, slot);
    } else {
        input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
    }
    
    input_sync(dev);
    stealth_dev->config.stats_moves++;
}

// 视角相关函数
static void hide_func(view_idle_work_func)(struct work_struct *work) {
    struct stealth_device *dev = container_of(work, struct stealth_device, view_idle_work);
    struct stealth_config *cfg = dev ? &dev->config : NULL;
    unsigned long flags;
    
    if (!dev || !cfg) return;
    
    spin_lock_irqsave(&dev->config_lock, flags);
    if (cfg->view.touch_held) {
        unsigned long curr_time = jiffies_to_msecs(jiffies);
        unsigned long delta_time = curr_time - cfg->view.last_move_time;
        
        if (delta_time >= VIEW_IDLE_TIMEOUT_MS) {
            hide_func(send_real_touch_event)(2, 0, 0, 0, &cfg->view.touch_state, -1, -1);
            cfg->view.touch_held = false;
            cfg->view.edge_reset_flag = false;
        } else {
            mod_timer(&dev->view_idle_timer, jiffies + msecs_to_jiffies(VIEW_IDLE_TIMEOUT_MS - delta_time));
        }
    }
    spin_unlock_irqrestore(&dev->config_lock, flags);
}
static void hide_func(view_idle_timer_func)(struct timer_list *t) {
    struct stealth_device *dev = from_timer(dev, t, view_idle_timer);
    if (dev && dev->workqueue) {
        queue_work(dev->workqueue, &dev->view_idle_work);
    }
}
static void hide_func(view_reset_work_func)(struct work_struct *work) {
    struct stealth_device *dev = container_of(work, struct stealth_device, view_reset_work);
    struct stealth_config *cfg = dev ? &dev->config : NULL;
    unsigned long flags;
    
    if (!dev || !cfg) return;
    
    spin_lock_irqsave(&dev->config_lock, flags);
    if (!cfg->view.touch_held || !cfg->view.edge_reset_flag) {
        spin_unlock_irqrestore(&dev->config_lock, flags);
        return;
    }
    hide_func(send_real_touch_event)(2, 0, 0, 0, &cfg->view.touch_state, -1, -1);
    cfg->view.touch_held = false;
    msleep(5);
    unsigned int rand_val;
    get_random_bytes(&rand_val, sizeof(rand_val));
    int reset_x = cfg->view.center_x + ((rand_val % (VIEW_RESET_JITTER * 2 + 1)) - VIEW_RESET_JITTER);
    int reset_y = cfg->view.center_y + (((rand_val >> 8) % (VIEW_RESET_JITTER * 2 + 1)) - VIEW_RESET_JITTER);
    cfg->view.current_x = reset_x;
    cfg->view.current_y = reset_y;
    cfg->view.touch_held = true;
    cfg->view.last_move_time = jiffies_to_msecs(jiffies);
    hide_func(send_real_touch_event)(2, reset_x, reset_y, 180, &cfg->view.touch_state, cfg->view.center_x, cfg->view.center_y);
    cfg->view.edge_reset_flag = false;
    spin_unlock_irqrestore(&dev->config_lock, flags);
}
static void hide_func(handle_view_move)(int dx, int dy) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!stealth_dev || !cfg->activated || !cfg->view.active) return;
    
    unsigned long curr_time = jiffies_to_msecs(jiffies);
    unsigned long flags;
    spin_lock_irqsave(&stealth_dev->config_lock, flags);
    
    int new_dx = (dx * cfg->view.sensitivity) / 100;
    int new_dy = (dy * cfg->view.sensitivity) / 100;
    
    if (!cfg->view.touch_held) {
        cfg->view.current_x = cfg->view.center_x;
        cfg->view.current_y = cfg->view.center_y;
        cfg->view.touch_held = true;
        cfg->view.edge_reset_flag = false;
    }
    cfg->view.current_x += new_dx;
    cfg->view.current_y += new_dy;
    
    int dx_center = cfg->view.current_x - cfg->view.center_x;
    int dy_center = cfg->view.current_y - cfg->view.center_y;
    int distance_sq = dx_center * dx_center + dy_center * dy_center;
    int distance = int_sqrt(distance_sq);
    if (distance > cfg->view.max_radius) {
        cfg->view.edge_reset_flag = true;
        queue_work(stealth_dev->workqueue, &stealth_dev->view_reset_work);
        spin_unlock_irqrestore(&stealth_dev->config_lock, flags);
        return;
    } else if (distance < cfg->view.deadzone) {
        spin_unlock_irqrestore(&stealth_dev->config_lock, flags);
        return;
    }
    
    cfg->view.last_move_time = curr_time;
    mod_timer(&stealth_dev->view_idle_timer, jiffies + msecs_to_jiffies(VIEW_IDLE_TIMEOUT_MS));
    hide_func(send_real_touch_event)(2, cfg->view.current_x, cfg->view.current_y, 180, &cfg->view.touch_state, cfg->view.center_x, cfg->view.center_y);
    
    spin_unlock_irqrestore(&stealth_dev->config_lock, flags);
}
// 滑动键处理
static void hide_func(handle_slide_key)(int dx, int dy) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!stealth_dev || !cfg->slide_key.enabled || !cfg->slide_key.active || !cfg->activated) return;
    
    int sensitivity = cfg->slide_key.sensitivity;
    int new_dx = (dx * sensitivity) / 100;
    int new_dy = (dy * sensitivity) / 100;
    
    // 跟随鼠标模式：滑动中心随鼠标移动（新增的核心逻辑）
    if (cfg->slide_key.mode == SLIDE_FOLLOW_MOUSE) {
        cfg->slide_key.slide_x = cfg->cursor.current_x;
        cfg->slide_key.slide_y = cfg->cursor.current_y;
    }
    
    int current_x = cfg->slide_key.current_x + new_dx;
    int current_y = cfg->slide_key.current_y + new_dy;
    
    int dx_slide = current_x - cfg->slide_key.slide_x;
    int dy_slide = current_y - cfg->slide_key.slide_y;
    int distance_sq = dx_slide * dx_slide + dy_slide * dy_slide;
    int distance = int_sqrt(distance_sq);
    if (distance > cfg->slide_key.max_radius) {
        current_x = cfg->slide_key.slide_x + (dx_slide * cfg->slide_key.max_radius) / distance;
        current_y = cfg->slide_key.slide_y + (dy_slide * cfg->slide_key.max_radius) / distance;
    }
    
    cfg->slide_key.current_x = current_x;
    cfg->slide_key.current_y = current_y;
    
    hide_func(send_real_touch_event)(3, current_x, current_y, 180, &cfg->slide_key.touch_state, cfg->slide_key.slide_x, cfg->slide_key.slide_y);
}

// 辅助函数
static const char *hide_func(key_name)(int keycode) {
    if (keycode >= KEY_RESERVED && keycode <= KEY_MAX) {
        static const char *key_names[] = {
            [KEY_0] = "KEY_0", [KEY_1] = "KEY_1", [KEY_2] = "KEY_2", [KEY_3] = "KEY_3", [KEY_4] = "KEY_4",
            [KEY_5] = "KEY_5", [KEY_6] = "KEY_6", [KEY_7] = "KEY_7", [KEY_8] = "KEY_8", [KEY_9] = "KEY_9",
            [KEY_A] = "KEY_A", [KEY_B] = "KEY_B", [KEY_C] = "KEY_C", [KEY_D] = "KEY_D", [KEY_E] = "KEY_E",
            [KEY_F] = "KEY_F", [KEY_G] = "KEY_G", [KEY_H] = "KEY_H", [KEY_I] = "KEY_I", [KEY_J] = "KEY_J",
            [KEY_K] = "KEY_K", [KEY_L] = "KEY_L", [KEY_M] = "KEY_M", [KEY_N] = "KEY_N", [KEY_O] = "KEY_O",
            [KEY_P] = "KEY_P", [KEY_Q] = "KEY_Q", [KEY_R] = "KEY_R", [KEY_S] = "KEY_S", [KEY_T] = "KEY_T",
            [KEY_U] = "KEY_U", [KEY_V] = "KEY_V", [KEY_W] = "KEY_W", [KEY_X] = "KEY_X", [KEY_Y] = "KEY_Y",
            [KEY_Z] = "KEY_Z", [KEY_ENTER] = "KEY_ENTER", [KEY_ESC] = "KEY_ESC", [KEY_BACKSPACE] = "KEY_BACKSPACE",
            [KEY_TAB] = "KEY_TAB", [KEY_SPACE] = "KEY_SPACE", [KEY_LEFTCTRL] = "KEY_LEFTCTRL", [KEY_LEFTSHIFT] = "KEY_LEFTSHIFT",
            [KEY_LEFTALT] = "KEY_LEFTALT", [KEY_LEFTMETA] = "KEY_LEFTMETA", [KEY_RIGHTCTRL] = "KEY_RIGHTCTRL",
            [KEY_RIGHTSHIFT] = "KEY_RIGHTSHIFT", [KEY_RIGHTALT] = "KEY_RIGHTALT", [KEY_RIGHTMETA] = "KEY_RIGHTMETA",
            [KEY_UP] = "KEY_UP", [KEY_DOWN] = "KEY_DOWN", [KEY_LEFT] = "KEY_LEFT", [KEY_RIGHT] = "KEY_RIGHT",
        };
        if (keycode < ARRAY_SIZE(key_names) && key_names[keycode])
            return key_names[keycode];
    }
    switch (keycode) {
        case BTN_LEFT: return "BTN_LEFT";
        case BTN_RIGHT: return "BTN_RIGHT";
        case BTN_MIDDLE: return "BTN_MIDDLE";
        case BTN_SIDE: return "BTN_SIDE";
        case BTN_EXTRA: return "BTN_EXTRA";
        default: break;
    }
    return NULL;
}
static void hide_func(generate_hidden_id)(unsigned char *id, int len) {
    int i;
    unsigned int rand_val;
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    
    for (i = 0; i < len; i++) {
        if (i % 4 == 0) get_random_bytes(&rand_val, sizeof(rand_val));
        id[i] = (rand_val >> ((i % 4) * 8)) & 0xFF;
    }
    id[0] ^= (ts.tv_sec >> 24) & 0xFF;
    id[1] ^= (ts.tv_sec >> 16) & 0xFF;
    id[2] ^= (ts.tv_sec >> 8) & 0xFF;
    id[3] ^= ts.tv_sec & 0xFF;
}
// 视角区域初始化
static void hide_func(init_view_area)(struct stealth_config *cfg) {
    if (!cfg) return;
    
    if (view_center_x >= 0 && view_center_x < cfg->screen_width) {
        cfg->view.center_x = view_center_x;
    } else {
        cfg->view.center_x = cfg->screen_width / 2;
    }
    
    if (view_center_y >= 0 && view_center_y < cfg->screen_height) {
        cfg->view.center_y = view_center_y;
    } else {
        cfg->view.center_y = cfg->screen_height / 2;
    }
    
    if (view_max_radius > 0) {
        cfg->view.max_radius = view_max_radius;
    } else {
        cfg->view.max_radius = cfg->screen_width / 5;
    }
    
    cfg->view.deadzone = view_deadzone;
    cfg->view.sensitivity = view_sensitivity;
    cfg->view.active = 1;
    cfg->view.touch_held = false;
    cfg->view.last_move_time = 0;
    cfg->view.edge_reset_flag = false;
    memset(&cfg->view.touch_state, 0, sizeof(struct real_touch_state));
    
    log_info("View area initialized: center=(%d,%d), radius=%d\n",
             cfg->view.center_x, cfg->view.center_y, cfg->view.max_radius);
}
static void hide_func(detect_screen_resolution)(struct stealth_config *cfg) {
    if (!cfg) return;
    
    cfg->screen_width = screen_width;
    cfg->screen_height = screen_height;
    
    if (cfg->screen_width <= 0 || cfg->screen_width > 8192)
        cfg->screen_width = 2800;
    if (cfg->screen_height <= 0 || cfg->screen_height > 8192)
        cfg->screen_height = 2000;
    
    log_info("Screen resolution: %dx%d\n", cfg->screen_width, cfg->screen_height);
    hide_func(init_view_area)(cfg);
    cfg->view.jitter_range = 8; // 按下时随机偏移±6像素（可自定义3~8）
cfg->view.touch_state.pressure_offset = 0; // 重置触摸状态，避免干扰
    
    cfg->slide_key.slide_x = cfg->screen_width * 3 / 10;
    cfg->slide_key.slide_y = cfg->screen_height * 6 / 10;
    cfg->joystick.center_x = cfg->screen_width * 7 / 10;
    cfg->joystick.center_y = cfg->screen_height * 7 / 10;
    cfg->cursor.current_x = cfg->screen_width / 2;
    cfg->cursor.current_y = cfg->screen_height / 2;
    
    memset(&cfg->slide_key.touch_state, 0, sizeof(struct real_touch_state));
    memset(&cfg->joystick.touch_state, 0, sizeof(struct real_touch_state));
    memset(&stealth_dev->default_touch_state, 0, sizeof(struct real_touch_state));
    // 轮盘默认配置（修改为 WASD 控制）
cfg->joystick.center_x = cfg->screen_width * 8 / 10;
cfg->joystick.center_y = cfg->screen_height * 8 / 10;
cfg->joystick.radius = 200;
cfg->joystick.deadzone = 20;
cfg->joystick.jitter_range = 3; // 原有：按下瞬间抖动
cfg->joystick.press_jitter_range = 11; // 新增：按住时持续抖动±8像素（可改5~12）
cfg->joystick.enabled = 1;
cfg->joystick.key_up = KEY_W;    // W → 上移
cfg->joystick.key_down = KEY_S;  // S → 下移
cfg->joystick.key_left = KEY_A;  // A → 左移
cfg->joystick.key_right = KEY_D; // D → 右移
} 

    static void hide_func(init_default_keymap)(struct stealth_config *cfg) {
    if (!cfg) return;
    
    struct key_mapping *km, *next;
    km = cfg->keymap_list;
    while (km) {
        next = km->next;
        kfree(km);
        km = next;
    }
    cfg->keymap_list = NULL;
    cfg->keymap_count = 0;
    
    log_info("Init default keymap: %d mappings\n", cfg->keymap_count);
}
// 配置保存/加载
static int hide_func(save_stealth_config)(void) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    struct file *file;
    loff_t pos = 0;
    int ret;
    
    if (!cfg) return -EINVAL;
    
    // 直接打开/data/smw.bin，无需创建隐藏目录
    file = filp_open(config_save_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (IS_ERR(file)) {
        log_info("Save config failed: open file error\n");
        return PTR_ERR(file);
    }
    
    struct config_header header = {0x51545343, 7};
    ret = kernel_write(file, &header, sizeof(header), &pos);
    if (ret != sizeof(header)) goto err;
    
    ret = kernel_write(file, &cfg->keymap_count, sizeof(int), &pos);
    if (ret != sizeof(int)) goto err;
    
    struct key_mapping *km = cfg->keymap_list;
    while (km) {
        struct key_map_serialize km_serial = {
            .keycode = km->keycode,
            .action = km->action,
            .x = km->params.hold.x,
            .y = km->params.hold.y,
            .duration = km->params.click.duration,
            .instant_release = km->instant_release,
            .jitter = km->jitter
        };
        ret = kernel_write(file, &km_serial, sizeof(km_serial), &pos);
        if (ret != sizeof(km_serial)) goto err;
        km = km->next;
    }
    
    ret = kernel_write(file, &g_real_touch_params, sizeof(struct real_touch_params), &pos);
    if (ret != sizeof(struct real_touch_params)) goto err;
    
    struct view_area_serialize view_serial = {
        .center_x = cfg->view.center_x,
        .center_y = cfg->view.center_y,
        .max_radius = cfg->view.max_radius,
        .deadzone = cfg->view.deadzone,
        .sensitivity = cfg->view.sensitivity
    };
    ret = kernel_write(file, &view_serial, sizeof(view_serial), &pos);
    if (ret != sizeof(view_serial)) goto err;
    
        // 写入轮盘配置（新增）
    struct joystick_serialize js_serial = {
        .center_x = cfg->joystick.center_x,
        .center_y = cfg->joystick.center_y,
        .radius = cfg->joystick.radius,
        .deadzone = cfg->joystick.deadzone,
        .jitter_range = cfg->joystick.jitter_range,
        .key_up = cfg->joystick.key_up,
        .key_down = cfg->joystick.key_down,
        .key_left = cfg->joystick.key_left,
        .key_right = cfg->joystick.key_right,
    };
    ret = kernel_write(file, &js_serial, sizeof(js_serial), &pos);
    if (ret != sizeof(js_serial)) goto err;

    // 写入全局配置（原有代码，保留）
    struct global_config_serialize global_serial = {
        .jitter_range = g_real_touch_params.jitter_range,
        .current_mode = cfg->current_mode,
        .view_area = view_serial,
        .joystick = js_serial // ✅ 关联轮盘配置
    };
    ret = kernel_write(file, &global_serial, sizeof(global_serial), &pos);
    if (ret != sizeof(global_serial)) goto err;

    
    filp_close(file, NULL);
    log_info("Config saved to %s\n", config_save_path);
    return 0;
err:
    filp_close(file, NULL);
    log_info("Save config failed at pos %lld\n", pos);
    return -EIO;
}
static int hide_func(load_stealth_config)(void) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    struct file *file;
    loff_t pos = 0;
    int ret, i, count;
    
    if (!cfg) return -EINVAL;
    
    // 打开/data/smw.bin，不存在则加载默认配置
    file = filp_open(config_save_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        log_info("Load config failed: file not found, use default\n");
        goto load_default;
    }
    
    struct config_header header;
    ret = kernel_read(file, &header, sizeof(header), &pos);
    if (ret != sizeof(header) || header.magic != 0x51545343) {
        log_info("Load config failed: invalid header\n");
        filp_close(file, NULL);
        goto load_default;
    }
    
    ret = kernel_read(file, &count, sizeof(int), &pos);
    if (ret != sizeof(int)) {
        filp_close(file, NULL);
        goto load_default;
    }
    
    struct key_mapping *km, *next;
    km = cfg->keymap_list;
    while (km) {
        next = km->next;
        kfree(km);
        km = next;
    }
    cfg->keymap_list = NULL;
    cfg->keymap_count = 0;
    
    for (i = 0; i < count; i++) {
        struct key_map_serialize km_serial;
        ret = kernel_read(file, &km_serial, sizeof(km_serial), &pos);
        if (ret != sizeof(km_serial)) {
            filp_close(file, NULL);
            goto load_default;
        }
        
        struct key_mapping *new_km = kzalloc(sizeof(struct key_mapping), GFP_KERNEL);
        if (!new_km) continue;
        
        new_km->keycode = km_serial.keycode;
        new_km->action = (km_serial.action >= 0 && km_serial.action <= 3) ? km_serial.action : 0;
        new_km->instant_release = km_serial.instant_release;
        new_km->jitter = km_serial.jitter;
        new_km->slot = i % 10;
        new_km->params.hold.x = km_serial.x;
        new_km->params.hold.y = km_serial.y;
        new_km->params.click.duration = km_serial.duration;
        
        const char *key_name_str = hide_func(key_name)(new_km->keycode);
        if (key_name_str) {
            snprintf(new_km->key_name, sizeof(new_km->key_name), "%s", key_name_str);
        } else {
            snprintf(new_km->key_name, sizeof(new_km->key_name), "Key (0x%04x)", new_km->keycode);
        }
        
        new_km->next = cfg->keymap_list;
        cfg->keymap_list = new_km;
        cfg->keymap_count++;
    }
    
    if (header.version >= 4) {
        ret = kernel_read(file, &g_real_touch_params, sizeof(struct real_touch_params), &pos);
        if (ret != sizeof(struct real_touch_params)) {
            log_info("Load real touch params failed, use default\n");
            g_real_touch_params.jitter_range = 3;
            g_real_touch_params.slide_accel = 120;
            g_real_touch_params.slide_decel = 80;
            g_real_touch_params.pressure_min = 80;
            g_real_touch_params.pressure_max = 200;
            g_real_touch_params.click_delay_range = 20;
        }
    }
    
    if (header.version >= 5) {
        struct view_area_serialize view_serial;
        ret = kernel_read(file, &view_serial, sizeof(view_serial), &pos);
        if (ret == sizeof(view_serial)) {
            cfg->view.center_x = view_serial.center_x;
            cfg->view.center_y = view_serial.center_y;
            cfg->view.max_radius = view_serial.max_radius;
            cfg->view.deadzone = view_serial.deadzone;
            cfg->view.sensitivity = view_serial.sensitivity;
            // 更新全局参数，让配置生效
            view_center_x = view_serial.center_x;
            view_center_y = view_serial.center_y;
            view_max_radius = view_serial.max_radius;
            view_deadzone = view_serial.deadzone;
            view_sensitivity = view_serial.sensitivity;
        }
    }
    
        struct global_config_serialize global_serial;
    ret = kernel_read(file, &global_serial, sizeof(global_serial), &pos);
    if (ret == sizeof(global_serial)) {
        cfg->current_mode = global_serial.current_mode;
        
        // 读取轮盘配置（新增）
        cfg->joystick.center_x = global_serial.joystick.center_x;
        cfg->joystick.center_y = global_serial.joystick.center_y;
        cfg->joystick.radius = global_serial.joystick.radius;
        cfg->joystick.deadzone = global_serial.joystick.deadzone;
        cfg->joystick.jitter_range = global_serial.joystick.jitter_range;
        cfg->joystick.key_up = global_serial.joystick.key_up;
        cfg->joystick.key_down = global_serial.joystick.key_down;
        cfg->joystick.key_left = global_serial.joystick.key_left;
        cfg->joystick.key_right = global_serial.joystick.key_right;
        cfg->joystick.enabled = 1; // 加载后自动启用轮盘
    }

    
    filp_close(file, NULL);
    log_info("Config loaded from %s, %d mappings\n", config_save_path, cfg->keymap_count);
    return 0;
load_default:
    hide_func(init_default_keymap)(cfg);
    return -EINVAL;
}
// 配置重载核心函数
static int hide_func(reload_smw_config)(void) {
    struct file *file;
    struct inode *inode;
    unsigned long mtime;
    int ret = 0;
    
    if (!stealth_dev) return -EINVAL;
    
    // 打开配置文件
    file = filp_open(config_save_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        log_info("Reload config failed: open file error\n");
        return PTR_ERR(file);
    }
    
    inode = file_inode(file);
    mtime = inode->i_mtime.tv_sec;
    
    // 仅当文件修改时间变化时才重载
    if (mtime != config_monitor.last_mtime) {
        log_info("Config file updated, start reloading...\n");
        
        // 锁定spinlock，避免配置更新时触发输入事件
        if (stealth_dev) { // 空指针检查
            spin_lock(&stealth_dev->config_lock);
            
            // 读取新配置（复用原有读取逻辑）
            ret = hide_func(load_stealth_config)();
            if (ret == 0) {
                config_monitor.last_mtime = mtime;
                // 重新初始化视角区域，让新配置生效
                hide_func(init_view_area)(&stealth_dev->config);
                log_info("Config reloaded successfully\n");
            } else {
                log_info("Config reload failed, keep old config\n");
            }
            
            spin_unlock(&stealth_dev->config_lock);
        }
    }
    
    filp_close(file, NULL);
    return ret;
}
// 配置监控工作队列回调（每2秒检查一次文件）
static void hide_func(config_monitor_workfn)(struct work_struct *work) {
    hide_func(reload_smw_config)();
    // 重新调度工作，实现循环监控
    schedule_delayed_work(&config_monitor.monitor_work, msecs_to_jiffies(2000));
}
// 按键学习相关
static void hide_func(learn_timeout_work_func)(struct work_struct *work) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!cfg) return;
    
    if (cfg->key_learn_active) {
        cfg->key_learn_active = 0;
        log_info("Key learn timeout (no key pressed)\n");
    }
}
static void hide_func(learn_timeout_timer_func)(struct timer_list *t) {
    struct stealth_device *dev = from_timer(dev, t, learn_timeout_timer);
    if (dev && dev->workqueue) {
        queue_work(dev->workqueue, &dev->learn_timeout_work);
    }
}
static void hide_func(start_key_learn)(struct stealth_config *cfg) {
    if (!cfg || cfg->key_learn_active) return;
    
    cfg->key_learn_active = 1;
    cfg->learned_keycode = -1;
    cfg->learn_timeout = 5;
    
    mod_timer(&stealth_dev->learn_timeout_timer, jiffies + msecs_to_jiffies(cfg->learn_timeout * 1000));
    log_info("Key learn started (timeout: %ds)\n", cfg->learn_timeout);
}
static void hide_func(stop_key_learn)(struct stealth_config *cfg) {
    if (!cfg || !cfg->key_learn_active) return;
    
    cfg->key_learn_active = 0;
    del_timer_sync(&stealth_dev->learn_timeout_timer);
    log_info("Key learn stopped\n");
}
static void hide_func(process_learned_key)(int code) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!cfg || !cfg->key_learn_active || code == -1) return;
    
    cfg->learned_keycode = code;
    cfg->key_learn_active = 0;
    del_timer_sync(&stealth_dev->learn_timeout_timer);
    
    const char *key_name_str = hide_func(key_name)(code);
    if (key_name_str) {
        log_info("Learned key: %s (keycode=0x%04x)\n", key_name_str, code);
    } else {
        log_info("Learned keycode: 0x%04x\n", code);
    }
    cfg->stats_learned_keys++;
}
// 按键映射处理
static struct key_mapping *hide_func(find_key_mapping)(int keycode) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!cfg) return NULL;
    
    struct key_mapping *km = cfg->keymap_list;
    while (km) {
        if (km->keycode == keycode) return km;
        km = km->next;
    }
    return NULL;
}
static void hide_func(handle_key_binding)(int keycode, int value) {
    struct key_mapping *km = hide_func(find_key_mapping)(keycode);
    if (!km || !stealth_dev || !stealth_dev->config.activated) return;
    
    int x = km->params.hold.x;
    int y = km->params.hold.y;
    int pressure = value ? hide_func(real_touch_get_pressure)(&stealth_dev->default_touch_state) : 0;
    if (km->jitter > 0) {
        hide_func(real_touch_add_jitter)(&x, &y);
    }
    hide_func(send_real_touch_event)(km->slot, x, y, pressure, &stealth_dev->default_touch_state, -1, -1);
    if (value) {
        log_info("Key press: %s -> (%d,%d)\n", km->key_name, x, y);
        stealth_dev->config.stats_clicks++;
    }
}
static void hide_func(update_joystick_state)(int keycode, int value) {
    struct stealth_config *cfg = stealth_dev ? &stealth_dev->config : NULL;
    if (!stealth_dev || !cfg->joystick.enabled || !cfg->activated) return;
    
    unsigned long flags;
    spin_lock_irqsave(&stealth_dev->config_lock, flags);
    if (keycode == cfg->joystick.key_up) {
        cfg->joystick.key_states = value ? (cfg->joystick.key_states | 0x01) : (cfg->joystick.key_states & ~0x01);
    } else if (keycode == cfg->joystick.key_down) {
        cfg->joystick.key_states = value ? (cfg->joystick.key_states | 0x02) : (cfg->joystick.key_states & ~0x02);
    } else if (keycode == cfg->joystick.key_left) {
        cfg->joystick.key_states = value ? (cfg->joystick.key_states | 0x04) : (cfg->joystick.key_states & ~0x04);
    } else if (keycode == cfg->joystick.key_right) {
        cfg->joystick.key_states = value ? (cfg->joystick.key_states | 0x08) : (cfg->joystick.key_states & ~0x08);
    }
    
    int dx = 0, dy = 0;
    // 修复cfgcfg笔误为cfg
    if (cfg->joystick.key_states & 0x01) dy -= 5;
    if (cfg->joystick.key_states & 0x02) dy += 5;
    if (cfg->joystick.key_states & 0x04) dx -= 5;
    if (cfg->joystick.key_states & 0x08) dx += 5;
    
    if (dx != 0 || dy != 0) {
        cfg->joystick.current_x += dx;
        cfg->joystick.current_y += dy;
        int dx_center = cfg->joystick.current_x - cfg->joystick.center_x;
        int dy_center = cfg->joystick.current_y - cfg->joystick.center_y;
        int distance_sq = dx_center * dx_center + dy_center * dy_center;
        int distance = int_sqrt(distance_sq);
        if (distance > cfg->joystick.radius) {
            cfg->joystick.current_x = cfg->joystick.center_x + (dx_center * cfg->joystick.radius) / distance;
            cfg->joystick.current_y = cfg->joystick.center_y + (dy_center * cfg->joystick.radius) / distance;
        }
        hide_func(send_real_touch_event)(cfg->joystick.move_slot, cfg->joystick.current_x, cfg->joystick.current_y, 150, &cfg->joystick.touch_state, cfg->joystick.center_x, cfg->joystick.center_y);
        hide_func(handle_slide_key)(dx, dy);
        cfg->joystick.active = 1;
    } else if (cfg->joystick.active) {
        hide_func(send_real_touch_event)(cfg->joystick.move_slot, 0, 0, 0, &cfg->joystick.touch_state, -1, -1);
        cfg->joystick.active = 0;
    }
    
    spin_unlock_irqrestore(&stealth_dev->config_lock, flags);
}
// IO控制与命令处理
static long hide_func(stealth_ioctl)(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct stealth_device *dev = filp->private_data;
    unsigned char buf[MAX_ENCRYPTED_LEN] = {0};
    unsigned char cmd_buf[MAX_CMD_LEN] = {0};
    size_t cmd_len = 0;
    int ret = 0;
    
    if (!dev) return -EINVAL;
    
    if (copy_from_user(buf, (void __user *)arg, sizeof(buf))) {
        return -EFAULT;
    }
    
    ret = hide_func(verify_command)(buf, sizeof(buf), cmd_buf, &cmd_len);
    if (ret != 0) {
        return -EACCES;
    }
    
    mutex_lock(&dev->lock);
    dev->config.stats_commands++;
    mutex_unlock(&dev->lock);
    
    switch (cmd_buf[0]) {
        case CMD_START_KEY_LEARN:
            hide_func(start_key_learn)(&dev->config);
            break;
        case CMD_STOP_KEY_LEARN:
            hide_func(stop_key_learn)(&dev->config);
            break;
        case CMD_SAVE_CONFIG:
            ret = hide_func(save_stealth_config)();
            break;
        case CMD_SET_REAL_TOUCH_PARAM:
            if (cmd_len >= sizeof(struct real_touch_params) + 1) {
                memcpy(&g_real_touch_params, cmd_buf + 1, sizeof(struct real_touch_params));
                log_info("Real touch params updated\n");
            } else {
                ret = -EINVAL;
            }
            break;
        case CMD_SET_VIEW_AREA:
            if (cmd_len >= sizeof(struct view_area_serialize) + 1) {
                struct view_area_serialize *view = (struct view_area_serialize *)(cmd_buf + 1);
                dev->config.view.center_x = view->center_x;
                dev->config.view.center_y = view->center_y;
                dev->config.view.max_radius = view->max_radius;
                dev->config.view.deadzone = view->deadzone;
                dev->config.view.sensitivity = view->sensitivity;
                log_info("View area updated: (%d,%d) R=%d\n", view->center_x, view->center_y, view->max_radius);
            } else {
                ret = -EINVAL;
            }
            break;
                    case CMD_SET_JOYSTICK_PARAM:
            if (cmd_len >= sizeof(struct joystick_serialize) + 1) {
                struct joystick_serialize *js = (struct joystick_serialize *)(cmd_buf + 1);
                spin_lock(&dev->config_lock);
                // 更新轮盘参数
                dev->config.joystick.center_x = js->center_x;
                dev->config.joystick.center_y = js->center_y;
                dev->config.joystick.radius = js->radius;
                dev->config.joystick.deadzone = js->deadzone;
                dev->config.joystick.jitter_range = js->jitter_range;
                dev->config.joystick.key_up = js->key_up;
                dev->config.joystick.key_down = js->key_down;
                dev->config.joystick.key_left = js->key_left;
                dev->config.joystick.key_right = js->key_right;
                dev->config.joystick.enabled = 1;
                spin_unlock(&dev->config_lock);
                log_info("Joystick updated: pos=(%d,%d), radius=%d, jitter=%d\n",
                         js->center_x, js->center_y, js->radius, js->jitter_range);
            } else {
                ret = -EINVAL;
            }
            break;
        case CMD_GET_JOYSTICK_PARAM:
            {
                struct joystick_serialize js;
                spin_lock(&dev->config_lock);
                // 读取当前轮盘参数
                js = (struct joystick_serialize){
                    .center_x = dev->config.joystick.center_x,
                    .center_y = dev->config.joystick.center_y,
                    .radius = dev->config.joystick.radius,
                    .deadzone = dev->config.joystick.deadzone,
                    .jitter_range = dev->config.joystick.jitter_range,
                    .key_up = dev->config.joystick.key_up,
                    .key_down = dev->config.joystick.key_down,
                    .key_left = dev->config.joystick.key_left,
                    .key_right = dev->config.joystick.key_right,
                };
                spin_unlock(&dev->config_lock);
                // 把参数返回给用户空间
                if (copy_to_user((void __user *)arg, &js, sizeof(js))) {
                    ret = -EFAULT;
                }
            }
            break;
            case CMD_ADD_KEY_MAPPING:
    if (cmd_len >= sizeof(struct key_map_serialize) + 1) {
        struct key_map_serialize *km_serial = (struct key_map_serialize *)(cmd_buf + 1);
        struct key_mapping *new_km = kzalloc(sizeof(struct key_mapping), GFP_KERNEL);
        if (!new_km) { ret = -ENOMEM; break; }
        
        new_km->keycode = km_serial->keycode;
        new_km->action = km_serial->action;
        new_km->instant_release = km_serial->instant_release;
        new_km->jitter = km_serial->jitter;
        new_km->slot = km_serial->keycode % 10; // 自动分配触摸槽位
        new_km->params.hold.x = km_serial->x;
        new_km->params.hold.y = km_serial->y;
        new_km->params.click.duration = km_serial->duration;
        
        // 设置按键名称
        const char *key_name_str = hide_func(key_name)(new_km->keycode);
        snprintf(new_km->key_name, sizeof(new_km->key_name), 
                 key_name_str ? key_name_str : "CustomKey(0x%04x)", new_km->keycode);
        
        spin_lock(&dev->config_lock);
        new_km->next = dev->config.keymap_list;
        dev->config.keymap_list = new_km;
        dev->config.keymap_count++;
        spin_unlock(&dev->config_lock);
        
        log_info("Added key mapping: %s -> (%d,%d), jitter=%d\n", 
                 new_km->key_name, new_km->params.hold.x, new_km->params.hold.y, new_km->jitter);
    } else {
        ret = -EINVAL;
    }
    break;

case CMD_DEL_KEY_MAPPING:
    if (cmd_len >= sizeof(int) + 1) {
        int keycode = *(int *)(cmd_buf + 1);
        spin_lock(&dev->config_lock);
        struct key_mapping *km = dev->config.keymap_list;
        struct key_mapping *prev = NULL;
        while (km) {
            if (km->keycode == keycode) {
                if (prev) prev->next = km->next;
                else dev->config.keymap_list = km->next;
                kfree(km);
                dev->config.keymap_count--;
                log_info("Deleted key mapping: keycode=0x%04x\n", keycode);
                break;
            }
            prev = km;
            km = km->next;
        }
        spin_unlock(&dev->config_lock);
    } else {
        ret = -EINVAL;
    }
    break;

        case CMD_RELOAD_CONFIG:
            ret = hide_func(reload_smw_config)();
            if (ret == 0) {
                log_info("Config reloaded successfully from %s\n", config_save_path);
            } else {
                log_info("Config reload failed\n");
            }
            break;
        default:
            ret = -ENOTTY;
            break;
    }
    
    return ret;
}
// 文件操作接口
static int hide_func(stealth_open)(struct inode *inode, struct file *filp) {
    struct stealth_device *dev = container_of(inode->i_cdev, struct stealth_device, cdev);
    filp->private_data = dev;
    return 0;
}
static int hide_func(stealth_release)(struct inode *inode, struct file *filp) {
    return 0;
}
static const struct file_operations stealth_fops = {
    .owner = THIS_MODULE,
    .open = hide_func(stealth_open),
    .release = hide_func(stealth_release),
    .unlocked_ioctl = hide_func(stealth_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    .compat_ioctl = hide_func(stealth_ioctl),
#endif
};
// 输入事件处理
static void hide_func(stealth_input_event)(struct input_handle *handle, unsigned int type, unsigned int code, int value) {
    struct stealth_device *dev = handle->private;
    unsigned long flags;
    
    if (!dev || (type != EV_KEY && type != EV_REL)) return;
    
    spin_lock_irqsave(&dev->config_lock, flags);
    int next_head = (dev->buffer_head + 1) % ARRAY_SIZE(dev->input_buffer);
    if (next_head != dev->buffer_tail) {
        dev->input_buffer[dev->buffer_head].type = type;
        dev->input_buffer[dev->buffer_head].code = code;
        dev->input_buffer[dev->buffer_head].value = value;
        dev->buffer_head = next_head;
        queue_work(dev->workqueue, &dev->input_work);
    }
    spin_unlock_irqrestore(&dev->config_lock, flags);
    
    // ✅ 关键：拦截事件，不传递给系统，系统原生键鼠失效
    return;
    // 注释掉原事件传递逻辑（默认不执行）
    // input_pass_event(handle, type, code, value);
}

static void hide_func(stealth_input_disconnect)(struct input_handle *handle) {
    input_close_device(handle);
}
// 输入处理器连接函数
static int hide_func(stealth_input_connect)(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id) {
    struct stealth_device *sdev = stealth_dev;
    struct input_handle *handle;
    int ret;
    
    if (!sdev || !dev) return -EINVAL;
    
    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;
    
    handle->dev = dev;
    handle->handler = handler;
    handle->private = sdev;
    
    ret = input_open_device(handle);
    if (ret) {
        kfree(handle);
        return ret;
    }
    
    ret = input_register_handle(handle);
    if (ret) {
        input_close_device(handle);
        kfree(handle);
        return ret;
    }
    // 新代码：内核API兼容替换，功能完全一致（屏蔽设备uevent广播）
dev_set_uevent_suppress(&dev->dev, 1);
    return 0;
}
// ========== sysfs参数接口（支持临时调整参数） ==========
static ssize_t jitter_range_show(struct device *dev, struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", g_real_touch_params.jitter_range);
}
static ssize_t jitter_range_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &g_real_touch_params.jitter_range);
    return count;
}
static ssize_t view_sensitivity_show(struct device *dev, struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", view_sensitivity);
}
static ssize_t view_sensitivity_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    sscanf(buf, "%d", &view_sensitivity);
    if (stealth_dev) {
        stealth_dev->config.view.sensitivity = view_sensitivity;
    }
    return count;
}
// 注册sysfs属性（仅保留常用可调参数）
static DEVICE_ATTR_RW(jitter_range);
static DEVICE_ATTR_RW(view_sensitivity);
// 补充 sysfs 属性数组（驱动加载必需）
static struct attribute *stealth_attrs[] = {
    &dev_attr_jitter_range.attr,
    &dev_attr_view_sensitivity.attr,
    NULL,
};
const struct attribute_group stealth_attr_group = {
    .attrs = stealth_attrs,
};
// 驱动初始化
static int __init stealth_driver_init(void) {
    int ret;
    struct input_dev *input_dev;
    
    // 初始化配置监控结构体
    memset(&config_monitor, 0, sizeof(config_monitor));
    
    // 分配设备结构体
    stealth_dev = kzalloc(sizeof(struct stealth_device), GFP_KERNEL);
    if (!stealth_dev) return -ENOMEM;
    
        // 初始化同步机制
    mutex_init(&stealth_dev->lock);
    spin_lock_init(&stealth_dev->config_lock);
    init_waitqueue_head(&stealth_dev->cmd_waitq);
    // 生成隐藏设备ID
    hide_func(generate_hidden_id)(stealth_dev->hidden_id, sizeof(stealth_dev->hidden_id));
    // 初始化输入设备
    input_dev = input_allocate_device();
    if (!input_dev) {
        ret = -ENOMEM;
        goto err_free_dev;
    }
    stealth_dev->input_dev = input_dev;
    // 设置输入设备信息
    input_dev->name = INPUT_NAME;
    input_dev->phys = "touch_mapper/input0";
    input_dev->id.bustype = BUS_VIRTUAL;
    input_dev->id.vendor = 0x1234;
    input_dev->id.product = 0x5678;
    input_dev->id.version = 0x0100;
    // 启用触摸相关事件类型
    __set_bit(EV_ABS, input_dev->evbit);
    __set_bit(EV_KEY, input_dev->evbit);
    __set_bit(EV_SYN, input_dev->evbit);
    __set_bit(BTN_TOUCH, input_dev->keybit);
    // 初始化多点触摸（适配GKI 6.1+内核）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
    input_mt_init_slots(input_dev, 10, INPUT_MT_DIRECT | INPUT_MT_DROP_UNUSED);
#else
    input_mt_init_slots(input_dev, 10, 0);
#endif
    // 设置触摸参数范围
    input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, 8192, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, 8192, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 30, 0, 0);
    // 注册输入设备
    ret = input_register_device(input_dev);
    if (ret) goto err_free_input;
    // 注册字符设备（用于用户态通信）
    ret = alloc_chrdev_region(&stealth_dev->devno, 0, 1, DRIVER_NAME);
    if (ret) goto err_unregister_input;
    cdev_init(&stealth_dev->cdev, &stealth_fops);
    stealth_dev->cdev.owner = THIS_MODULE;
    ret = cdev_add(&stealth_dev->cdev, stealth_dev->devno, 1);
    if (ret) goto err_unregister_chrdev;
    // 创建设备类
    stealth_dev->class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(stealth_dev->class)) {
        ret = PTR_ERR(stealth_dev->class);
        goto err_del_cdev;
    }
    // 创建匿名设备（无/dev可见节点）
    stealth_dev->device = kzalloc(sizeof(struct device), GFP_KERNEL);
stealth_dev->device->class = stealth_dev->class;
    if (IS_ERR(stealth_dev->device)) {
        ret = PTR_ERR(stealth_dev->device);
        goto err_destroy_class;
    }
    // 设备创建成功，关联sysfs属性组（修复资源泄漏）
ret = sysfs_create_group(&stealth_dev->device->kobj, &stealth_attr_group);
if (ret) {
    pr_err("Failed to create sysfs group for device\n");
    device_destroy(stealth_dev->class, stealth_dev->devno);
    goto err_destroy_device; // ✅ 跳专属分支，避免泄漏
}

    // 初始化工作队列
    stealth_dev->workqueue = create_singlethread_workqueue(DRIVER_NAME);
    if (!stealth_dev->workqueue) {
        ret = -ENOMEM;
        goto err_destroy_device;
    }
    // 初始化工作项
    INIT_WORK(&stealth_dev->input_work, hide_func(input_work_func));
    INIT_WORK(&stealth_dev->learn_timeout_work, hide_func(learn_timeout_work_func));
    INIT_WORK(&stealth_dev->view_idle_work, hide_func(view_idle_work_func));
    INIT_WORK(&stealth_dev->view_reset_work, hide_func(view_reset_work_func));
    // 初始化定时器
    timer_setup(&stealth_dev->learn_timeout_timer, hide_func(learn_timeout_timer_func), 0);
    timer_setup(&stealth_dev->view_idle_timer, hide_func(view_idle_timer_func), 0);
        // 初始化MD5加密算法（适配GKI白名单）
#ifdef HAVE_CRYPTO_ALLOC_HASH
// 直接调用内核原生函数（因为动态查找代码被宏屏蔽）
stealth_dev->md5_tfm = crypto_alloc_shash("md5", 0, GFP_KERNEL);
#else
// 动态查找逻辑（宏未定义时生效，当前不执行）
ret = find_crypto_symbols();
if (ret != 0) {
    log_info("Crypto symbols not found\n");
    goto err_destroy_workqueue;
}
stealth_dev->md5_tfm = safe_crypto_alloc_shash("md5", 0, GFP_KERNEL);
#endif
if (IS_ERR(stealth_dev->md5_tfm)) {
    ret = PTR_ERR(stealth_dev->md5_tfm);
    stealth_dev->md5_tfm = NULL;
    log_info("Crypto init failed: %d\n", ret);
    goto err_destroy_workqueue;
}


    // 注册输入处理器
    ret = input_register_handler(&stealth_input_handler);
    if (ret) goto err_free_crypto;
    // 初始化配置（开机自动加载/data/smw.bin）
    hide_func(detect_screen_resolution)(&stealth_dev->config);
    hide_func(init_default_keymap)(&stealth_dev->config);
    stealth_dev->config.activated = 1; // ✅ 运行时设置默认激活
    hide_func(load_stealth_config)();
    // 启用Proc隐藏（合规版）
    if (!hide_func(init_proc_hide)()) {
        log_info("Proc hide init warning\n");
    }
    // 初始化配置监控（实时响应配置变更）
    INIT_DELAYED_WORK(&config_monitor.monitor_work, hide_func(config_monitor_workfn));
    // 首次延迟1秒启动监控
    schedule_delayed_work(&config_monitor.monitor_work, msecs_to_jiffies(1000));
    log_info("Config monitor started, real-time response to changes\n");
    // 驱动加载成功日志
    log_info("Stealth touch mapper driver loaded (v4.2 FINAL) - config path: %s\n", config_save_path);
    hide_func(stealth_hide_mem_signature)(); // 新增：隐藏内存特征
    return 0;
    // 错误处理流程（修复资源泄漏）
err_free_crypto:
    #ifdef HAVE_CRYPTO_ALLOC_HASH
    crypto_free_shash(stealth_dev->md5_tfm); // 直接调用内核函数（宏生效时）
    #else
    safe_crypto_free_shash(stealth_dev->md5_tfm); // 动态查找时的备用逻辑
    #endif


err_destroy_workqueue:
    destroy_workqueue(stealth_dev->workqueue);
err_destroy_device: // ✅ 修复：仅销毁一次，跳过重复分支
    class_destroy(stealth_dev->class); // 唯一一次销毁类资源
    goto err_del_cdev; // 直接跳转到 err_del_cdev，跳过 err_destroy_class
err_destroy_class:
    class_destroy(stealth_dev->class); // 仅处理正常创建类后的销毁（无重复）
err_del_cdev:
    cdev_del(&stealth_dev->cdev);

err_unregister_chrdev:
    unregister_chrdev_region(stealth_dev->devno, 1);
err_unregister_input:
    input_unregister_device(input_dev);
err_free_input:
    input_free_device(input_dev);
err_free_dev:
    kfree(stealth_dev);
    return ret;
}

// 驱动退出（完整清理，无残留）
static void __exit stealth_driver_exit(void) {
    if (!stealth_dev) return;
    // 停止定时器
    if (timer_pending(&stealth_dev->learn_timeout_timer))
        del_timer_sync(&stealth_dev->learn_timeout_timer);
    if (timer_pending(&stealth_dev->view_idle_timer))
        del_timer_sync(&stealth_dev->view_idle_timer);
    // 停止配置监控工作队列
    if (work_pending(&config_monitor.monitor_work.work)) {
        cancel_delayed_work_sync(&config_monitor.monitor_work);
        flush_delayed_work(&config_monitor.monitor_work);
    }
    // 注销输入处理器
    input_unregister_handler(&stealth_input_handler);
    // 释放加密资源
if (stealth_dev->md5_tfm) {
    #ifdef HAVE_CRYPTO_ALLOC_HASH
    crypto_free_shash(stealth_dev->md5_tfm); // 直接调用内核原生函数
    #else
    safe_crypto_free_shash(stealth_dev->md5_tfm); // 动态查找时的备用逻辑
    #endif
    stealth_dev->md5_tfm = NULL;
}


    // 销毁工作队列
    if (stealth_dev->workqueue) {
        destroy_workqueue(stealth_dev->workqueue);
        stealth_dev->workqueue = NULL;
    }
    // 清理sysfs属性组和设备节点
    if (stealth_dev->device) {
        sysfs_remove_group(&stealth_dev->device->kobj, &stealth_attr_group);
        device_destroy(stealth_dev->class, stealth_dev->devno);
    }
    // 清理设备类
    if (stealth_dev->class && !IS_ERR(stealth_dev->class)) {
        class_destroy(stealth_dev->class);
    }
    // 注销字符设备
    cdev_del(&stealth_dev->cdev);
    unregister_chrdev_region(stealth_dev->devno, 1);
    // 注销输入设备
    if (stealth_dev->input_dev) {
        input_unregister_device(stealth_dev->input_dev);
        input_free_device(stealth_dev->input_dev);
        stealth_dev->input_dev = NULL;
    }
    // 关闭Proc隐藏
    hide_func(exit_proc_hide)();
    // 清理按键映射链表
    if (stealth_dev->config.keymap_list) {
        struct key_mapping *km = stealth_dev->config.keymap_list;
        while (km) {
            struct key_mapping *next = km->next;
            kfree(km);
            km = next;
        }
        stealth_dev->config.keymap_list = NULL;
    }
    // 清理模块痕迹（合规版）
    hide_func(stealth_clean_trace)();
    // 驱动卸载日志
    log_info("Stealth touch mapper driver unloaded\n");
    // 释放设备结构体
    kfree(stealth_dev);
    stealth_dev = NULL;
}
// 驱动初始化/退出入口
module_init(stealth_driver_init);
module_exit(stealth_driver_exit);
// 模块信息（GPL协议兼容内核）
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Stealth Touch Mapper Driver (Keyboard/Mouse to Touch) - Built-in boot compatible");
MODULE_VERSION("4.2 FINAL");
MODULE_AUTHOR("Kernel Dev");
