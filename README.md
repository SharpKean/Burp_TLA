# Burp插件_TLA Watcher

## 开发环境

```
Java版本11.0.15.1
```

## 更新说明V1.3（2025.11.12）

本次版本迭代，优化的核心在于改进过滤器和线程管理的方式，以更好地支持目录扫描、XSS检测等现有及未来的扩展模块，具体更新如下：

✅ 优化扩展功能模块

1).对过滤器和线程数进行了统一的管理，改为全局

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE3HA8eWaiaGgFpoutBbibQ66pOI9HCH48QxNApkB5A3MrHMGcJWQQCTDqsibatjpib0Onx3ib7a0ibRDEHg/640)

## 更新说明V1.2（2025.08.03）

这里感谢【tang51678】提出的建议

本次版本更新主要涉及：Bug修复、功能新增优化，具体更新如下：

✅ 修复流量管理模块中排序后删除错乱的问题

1).此前因用户进行降序排序后进行删除数据时，仍按升序ID删除，导致误删数据，现已修正为**准确删除目标记录**；

✅ 增强条件判定

1).未选中数据时将**弹出温馨提示**，避免误操作；

✅ 性能与界面优化

1).流量管理模块新增**发送Repeater功能和复制URL功能**支持右键**单个/批量**发送到burp。

```
要查看更新功能的演示，请访问此处：https://mp.weixin.qq.com/s/hPlCuOJs5o_r2Wlo8GOj9Q
```

## 更新说明V1.1（2025.07.11）

本次版本迭代主要围绕性能优化、交互改进、功能扩展三大方向进行升级，具体更新如下：

✅ 名称变更

1).原插件名称 **TLA** 正式更名为 **TLA Watcher**

✅ 性能与界面优化

1).摒弃原有的分页加载方式，改为**滚动条实时加载数据**，提高了浏览流畅度与交互体验

✅ 检索功能增强

1).支持对**所有字段**（如URL、Remarks、Request、Response等）进行**模糊检索**

✅ 扩展功能模块——目录扫描

1).引入域名自动**去重机制**，避免重复扫描

✅ 扩展功能模块——新增XSS检测
1).参数覆盖全面，自动筛选参数
2).模拟真实访问行为，不会**触发WAF告警**
3).支持批量发送至 **Burp Repeater 模块**，便于进一步复现与验证

```
要查看更新功能的演示，请访问此处：https://mp.weixin.qq.com/s/bimRAEvlDhfzJQroIuBsGw
```

## 流程图

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE206u8pWCxibGXVFZQQPDib6bW71TQcVkKtGTY98siblq6xmjkhIZu8v5Zm5Kbw2ZyzUv3gJM9J6Inug/640)

## 功能介绍

```
TLA Watcher 主要由两个核心模块组成：流量管理模块 和 扩展功能模块，分别用于流量记录与分析、以及辅助漏洞挖掘。
```

📌 **流量记录**

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOOH6S6JQdjRSHrsK3xhXmXvfP4uFUHKrRuEuMro8XKqiarbLfWf4NUXQ/640)

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOqicoD8Voga2qKLkelibtfFxP6GdhUytYBiamutzAplAOGxf4ic5alzljSQ/640)

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOYbz5ia7hcjb82WTR4jDRlVlgpnvNK6Rd7FFyicua0PA5cO40SvebPRYQ/640)

🔍 **模糊检索**

​	提供下拉选择器支持对**所有字段模糊检索**，灵活匹配所需内容

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOAibbzcEpGicAeugZ4PjYTeiaQ2NQcd8AE31fLsBo9rkoncArpV6xtEibhQ/640)

✏️ **流量管理**

​	支持实时修改与批量删除记录，**数据持久化存储于本地SQLite数据库，重启插件后数据不丢失**

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOib2jRxgh10l78j1B6Wo2HrS4fVicDtc2sr65yaf4PO1aREvdl1Wofaicg/640)

🧵**目录扫描**

​	支持自定义扫描类型（如常见**敏感目录、备份文件、API 接口**等）,可导入任意格式的.txt字典文件，适配不同业务场景

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvObSyexQnmxQvAAtWibC8oRyVD0nOFpvl6AeynIXvMOYDt7iaibuibUfySQg/640)

🔄 **动态切换**

​	支持实时切换扫描类型，并可配置白名单过滤器，确保白名单中的域名不受扫描影响

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOOnInCfAAzV9nyRLBvslFk95jgqrjt5ricbJcClu8HP2n6hZRa1zSE6Q/640)

💡 **XSS检测**

​	支持GET、POST和文件上传类型的参数检测，低误报，模拟正常用户行为，不携带恶意载荷，**避免触发WAF规则**，同时进行了降噪处理，确保检测过程的准确性与安全性

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvO3F2d6B7WWZEwOB2ueBStGc3ky3LAogOFzq5uLHiadGdmC1GicNaWN2Sg/640)

​	支持将检测出的 XSS 漏洞**批量发送到 Burp Repeater 模块**，方便快速复现与验证

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE2ibkIFhiaptTLPMtsUXYBdvOvRsmY82Bdzmv5jncIwvIrnoZjpAm7zzGtpgvA9XZUPcBHPomcYOeSA/640)

## 后续更新

```
在TLA Watcher V1.4版本中
XSS检测模块新增对 Referer 和 Cookie 、JSON格式的检测支持，发现更多的可能性；
同时新增了SSTI检测模块，但该模块目前尚未完善，将在后续版本中完成并一同迭代发布。
```

![image-20240229163245151](https://mmbiz.qpic.cn/mmbiz_png/8h5fX1cyibE3HA8eWaiaGgFpoutBbibQ66pxx1cDQTIW2z4ocVf1oibHZCR1wkgibFdXRgYaoNzdCTfTpmfCtEEIe9A/640)

## 常见问题

```
1、db文件无法导入的问题？
答：编辑db文件属性，取消只读。
```

```
2、插件如何存储流量记录和配置，重启后如何恢复上次的设置？
答：流量记录存储在数据库，配置保存在配置文件，插件重启时自动加载。
```

```
3、是否支持批量删除数据？
答：支持。
```

## 公众号

```
信安脉络Sec，获取最新更新信息与详情！！！
```

## 免责声明 

请勿利用本文提供的技术从事非法活动。文章仅供学习目的使用，所涉及的工具仅限于安全研究和学习之用。若将工具用于其他目的，使用者须承担全部法律及连带责任。作者及发布者不承担任何法律及连带责任。