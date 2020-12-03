# openvpn-admin
一个简单的openvpn的web管理工具， 基于sanic web框架，支持3.6以上。

# 安装依赖

```
python3 -m pip install -r requirements.txt
```
服务运行需要安装redis服务。
# 配置文件
配置文件见 config.py

openvpn的默认配置文件见 conf.d目录
server.conf中python3的地址需要根据系统实际情况修改
# 执行
不需要事先启动openvpn服务，也不需要事先生成证书，服务启动时会自动生成证书，如有已生成的证书，需要拷贝到conf.d目录并建议按照默认的命名，否则需要修改server.conf, client.conf中的证书文件的命名。

保证openvpn文件在path目录下，即保证openvpn命令可以直接执行， 服务启动后会自动启动openvpn进程

执行前需要修改配置文件， 然后执行`python3 init_db.py`来初始化数据库表和创建管理员账号，（只需要一次）

然后执行
```
python3 app.py
```
浏览器访问`http://127.0.0.1:12345`

# 用法

1. 用户界面的表格右上角加号可添加用户， 云图标下载客户端配置， 解压后window需修改client.conf后缀名为`.ovpn`
2. 日志界面只会有最多200条记录
3. 配置文件修改后需要重启openvpn服务，才会生效， 建议不要频繁重启openvpn服务， 可能导致断开钩子没法正常执行
4. 管理界面集成了openvpn自带的服务管理功能， 需要在配置文件中加上`management [ip] [port]`来开通

# TODO
1. 未提供界面断开连接按钮，使用管理界面的`kill [cn]`命令断开连接
2. 表格的分页目前没有实现
3. 用户界面未实现搜索功能
4. 未提供用户禁用功能，会直接删除该用户记录
5. 可能会有未知页面样式问题
6. 根据客户端的操作系统，下载客户端时自动修改配置文件后缀名
7. 未能实时更新传输字节数，依赖断开钩子函数更新

这些功能会在以后版本中实现，敬请期待。

# 部署
supervisor 管理进程

nginx反代，注意websocket的字段
