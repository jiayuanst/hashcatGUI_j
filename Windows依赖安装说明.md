# HashcatGUI Windows 依赖安装说明

## 概述
HashcatGUI 支持多种文件类型的密码破解，包括：

### 完全支持（无需额外依赖）
- **压缩文件**：ZIP、RAR、7-Zip
- **密码管理器**：KeePass（.kdbx, .kdb）

### 需要Python支持的文件类型
- **Office文档**：.doc, .docx, .xls, .xlsx, .ppt, .pptx
- **OpenDocument文件**：.odt, .ods, .odp, .odg, .odf
- **StarOffice文件**：.sxc, .sxw, .sxi, .sxd
- **密码管理器**：Password Safe (.psafe3)、Enpass (.enpassdb, .walletx)、Bitwarden (.db)
- **加密货币钱包**：Bitcoin (.dat, .wallet)、Ethereum (.json, .keystore)、MultiBit (.multibit)、Electrum (.electrum)
- **Apple文件**：iWork (.key, .numbers, .pages)、Keychain (.keychain)、DMG (.dmg)
- **磁盘加密**：TrueCrypt/VeraCrypt (.tc, .hc)、LUKS (.luks, .img)
- **文件加密**：AxCrypt (.axx)、EncFS (.encfs6.xml)
- **应用程序**：Lotus Notes (.id, .nsf)、Mozilla (.key3.db, .key4.db)、FileZilla (.xml)

### 需要Perl支持的文件类型
- **PDF文件**：.pdf
- **iTunes备份**：.plist

## 依赖安装

### 1. Python 安装（用于大多数文件类型）

#### 方法一：从官网下载
1. 访问 [Python官网](https://www.python.org/downloads/)
2. 下载最新版本的Python（推荐3.8+）
3. 安装时**务必勾选"Add Python to PATH"**
4. 验证安装：打开命令提示符，输入 `python --version`

#### 方法二：使用Microsoft Store
1. 打开Microsoft Store
2. 搜索"Python"
3. 安装Python 3.x版本

### 2. Perl 安装（用于PDF和iTunes备份文件）

#### 推荐：Strawberry Perl
1. 访问 [Strawberry Perl官网](http://strawberryperl.com/)
2. 下载Windows版本
3. 运行安装程序（会自动添加到PATH）
4. 验证安装：打开命令提示符，输入 `perl --version`

#### 备选：ActivePerl
1. 访问 [ActiveState官网](https://www.activestate.com/products/perl/)
2. 下载ActivePerl
3. 安装并确保添加到PATH

## 支持的文件类型详细说明

### 密码管理器
- **KeePass** (.kdbx, .kdb)：流行的开源密码管理器
- **Password Safe** (.psafe3)：Bruce Schneier设计的密码管理器
- **Enpass** (.enpassdb, .walletx)：跨平台密码管理器
- **Bitwarden** (.db)：开源密码管理器

### 加密货币钱包
- **Bitcoin** (.dat, .wallet)：Bitcoin Core钱包文件
- **Ethereum** (.json, .keystore)：以太坊钱包文件
- **MultiBit** (.multibit)：轻量级Bitcoin钱包
- **Electrum** (.electrum)：轻量级Bitcoin钱包

### 磁盘加密
- **TrueCrypt/VeraCrypt** (.tc, .hc)：全盘加密软件
- **LUKS** (.luks, .img)：Linux统一密钥设置

### Apple生态
- **iWork** (.key, .numbers, .pages)：Apple办公套件
- **iTunes备份** (.plist)：iOS设备备份文件
- **Keychain** (.keychain)：macOS钥匙串
- **DMG** (.dmg)：macOS磁盘镜像

### 其他应用程序
- **Lotus Notes** (.id, .nsf)：IBM协作软件
- **Mozilla** (.key3.db, .key4.db)：Firefox/Thunderbird密码数据库
- **FileZilla** (.xml)：FTP客户端配置文件
- **AxCrypt** (.axx)：文件加密软件
- **EncFS** (.encfs6.xml)：加密文件系统

## 错误处理

### 常见错误及解决方案

1. **"Python未安装或不可用"**
   - 确保Python已正确安装
   - 检查PATH环境变量是否包含Python路径
   - 重启HashcatGUI

2. **"Perl未安装"**
   - 安装Strawberry Perl或ActivePerl
   - 确保Perl已添加到系统PATH
   - 重启命令提示符和HashcatGUI

3. **"工具不存在"**
   - 确保JohnTheRipper路径设置正确
   - 检查对应的2john工具是否存在于JohnTheRipper目录中
   - 某些新增的工具可能在旧版本的JohnTheRipper中不存在

4. **"权限不足"**
   - 以管理员身份运行HashcatGUI
   - 检查文件是否被其他程序占用

5. **"不支持的文件类型"**
   - 检查文件扩展名是否正确
   - 确保使用的是支持的文件格式
   - 某些文件可能需要特定的JohnTheRipper版本

## 验证安装

安装完成后，可以通过以下方式验证：

1. **Python验证**：
   ```cmd
   python --version
   ```

2. **Perl验证**：
   ```cmd
   perl --version
   ```

3. **功能测试**：
   - 尝试破解一个简单的Office文档（测试Python）
   - 尝试破解一个简单的PDF文件（测试Perl）
   - 测试不同类型的文件以验证支持情况

## 注意事项

- 安装Python或Perl后，可能需要重启HashcatGUI才能生效
- 如果仍有问题，请检查系统环境变量PATH设置
- 某些杀毒软件可能会误报，请添加到白名单
- 建议使用最新版本的Python和Perl以获得最佳兼容性
- 不同版本的JohnTheRipper可能支持的工具有所不同
- 某些文件类型可能需要特定的依赖库，如果遇到问题请查看JohnTheRipper文档