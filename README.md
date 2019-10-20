# openvpn-admdin
一个简单的openvpn的web管理工具， 基于sanic web框架，支持3.6以上。

# 安装依赖

```
python3 -m pip install -r requirements.txt
```

# 配置文件
配置文件见 config.py
openvpn的默认配置文件见 conf.d目录

# 执行
执行前需要执行`python3 init_db.py`来初始化数据库表和创建管理员账号，
然后执行
```
python3 app.py
```
浏览器访问`http://127.0.0.1:12345`
# 部署 
supervisor 管理进程
nginx反代，注意websocket的字段