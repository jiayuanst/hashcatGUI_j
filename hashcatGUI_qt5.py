#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import subprocess
import threading
import time
import logging
import locale
import datetime
from typing import Optional, Tuple, Dict, List, Any, Set
from functools import lru_cache
try:
    from pypinyin import pinyin, lazy_pinyin, Style
    PINYIN_AVAILABLE = True
except ImportError:
    PINYIN_AVAILABLE = False

# 配置日志记录
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hashcat_gui_function_calls.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
function_logger = logging.getLogger('FunctionCalls')
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox,
    QCheckBox, QFileDialog, QMessageBox, QGroupBox, QGridLayout,
    QRadioButton, QButtonGroup, QProgressBar, QSplitter, QDialog,
    QDialogButtonBox, QSpinBox, QFrame, QScrollArea, QProgressDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QMimeData, QTimer
from PyQt5.QtGui import QFont, QIcon, QDrag, QPalette

# 常量定义
class HashTypes:
    """哈希类型常量"""
    MD5 = '0'
    SHA1 = '100'
    SHA256 = '1400'
    SHA512 = '1700'
    BCRYPT = '3200'
    NTLM = '1000'
    SHA512CRYPT = '1800'
    MD5CRYPT = '500'
    DESCRYPT = '1500'
    PHPASS = '400'
    
    # 网络协议
    WPA_EAPOL = '2500'
    WPA_PMKID = '16800'
    WPA_PBKDF2 = '22000'
    
    # 数据库
    MSSQL_2000 = '131'
    MSSQL_2005 = '132'
    MSSQL_2012 = '1731'
    MYSQL323 = '200'
    MYSQL41 = '300'
    
    # 加密货币
    BITCOIN_WALLET = '11300'
    ELECTRUM_WALLET = '16600'
    
    # Office文档
    OFFICE_2007 = '9400'
    OFFICE_2010 = '9500'
    OFFICE_2013 = '9600'
    OFFICE_OLD_MD5 = '9700'
    OFFICE_OLD_SHA1 = '9800'
    
    # PDF文档
    PDF_1_1_1_3 = '10400'
    PDF_1_4_1_6 = '10500'
    PDF_1_7_L3 = '10600'
    PDF_1_7_L8 = '10700'
    
    # 压缩文件
    SEVEN_ZIP = '11600'
    RAR3_HP = '12500'
    RAR5 = '13000'
    RAR3_P_UNCOMPRESSED = '23700'
    RAR3_P_COMPRESSED = '23800'
    WINZIP = '13600'
    PKZIP = '17200'
    
    # 其他格式
    ODF_1_2 = '18400'
    ODF_1_1 = '18600'
    APPLE_IWORK = '23300'
    
    # 密码管理器
    KEEPASS_1_X = '13400'
    KEEPASS_2_X = '13400'
    PWSAFE_V3 = '5200'
    ENPASS_5 = '25800'
    ENPASS_6 = '25900'
    BITWARDEN = '24100'
    
    # 加密货币钱包
    BITCOIN_CORE = '11300'
    BITCOIN_CORE_ENCRYPTED = '16600'
    ETHEREUM_WALLET = '15700'
    ETHEREUM_PRESALE = '15600'
    MULTIBIT_HD = '16700'
    ELECTRUM_WALLET_NEW = '16800'
    
    # 磁盘加密
    TRUECRYPT_RIPEMD160 = '6211'
    TRUECRYPT_SHA512 = '6221'
    TRUECRYPT_WHIRLPOOL = '6231'
    TRUECRYPT_RIPEMD160_BOOT = '6241'
    TRUECRYPT_SHA512_BOOT = '6242'
    TRUECRYPT_WHIRLPOOL_BOOT = '6243'
    VERACRYPT_RIPEMD160 = '13711'
    VERACRYPT_SHA256 = '13712'
    VERACRYPT_SHA512 = '13713'
    VERACRYPT_WHIRLPOOL = '13714'
    VERACRYPT_STREEBOG = '13715'
    LUKS = '14600'
    
    # 文件加密
    AXCRYPT = '23100'
    AXCRYPT_IN_MEMORY_SHA1 = '23200'
    ENCFS = '22400'
    
    # Apple相关
    ITUNES_BACKUP_9 = '14700'
    ITUNES_BACKUP_10 = '14800'
    APPLE_KEYCHAIN = '23100'
    DMG = '18300'
    
    # 应用程序
    LOTUS_NOTES_DOMINOSEC = '8700'
    MOZILLA_KEY3 = '3200'
    MOZILLA_KEY4 = '16900'
    FILEZILLA_SERVER = '15000'
    STAROFFICE = '18400'

class AttackModes:
    """攻击模式常量"""
    DICTIONARY = '0'
    COMBINATION = '1'
    MASK = '3'
    HYBRID_DICT_MASK = '6'
    HYBRID_MASK_DICT = '7'
    ASSOCIATION = '9'
    
    # 攻击模式分组
    DICTIONARY_MODES = [DICTIONARY, COMBINATION, HYBRID_DICT_MASK, HYBRID_MASK_DICT]
    MASK_MODES = [MASK, HYBRID_DICT_MASK, HYBRID_MASK_DICT]

class WorkloadProfiles:
    """工作负载配置常量"""
    LOW = '1'
    DEFAULT = '2'
    HIGH = '3'
    NIGHTMARE = '4'

# 拖拽相关的自定义控件
class DraggableLabel(QLabel):
    """可拖拽的标签"""
    def __init__(self, text, charset):
        function_logger.debug(f"DraggableLabel.__init__ called with text='{text}', charset='{charset}'")
        super().__init__(text)
        self.charset = charset
        self.setStyleSheet("""
            QLabel {
                border: 2px solid #3498db;
                border-radius: 5px;
                padding: 5px;
                background-color: #ecf0f1;
                color: #2c3e50;
            }
            QLabel:hover {
                background-color: #bdc3c7;
                border-color: #2980b9;
            }
        """)
        self.setMinimumHeight(30)
        
    def mousePressEvent(self, event):
        function_logger.debug(f"DraggableLabel.mousePressEvent called")
        if event.button() == Qt.LeftButton:
            self.drag_start_position = event.pos()
            
    def mouseMoveEvent(self, event):
        function_logger.debug(f"DraggableLabel.mouseMoveEvent called")
        if not (event.buttons() & Qt.LeftButton):
            return
            
        if ((event.pos() - self.drag_start_position).manhattanLength() < 
            QApplication.startDragDistance()):
            return
            
        drag = QDrag(self)
        mimeData = QMimeData()
        mimeData.setText(self.charset)
        drag.setMimeData(mimeData)
        
        dropAction = drag.exec_(Qt.CopyAction)

class DropTargetLineEdit(QLineEdit):
    """支持拖拽接收的输入框"""
    def __init__(self):
        function_logger.debug(f"DropTargetLineEdit.__init__ called")
        super().__init__()
        self.setAcceptDrops(True)
        self.charset_number = 0
        
    def dragEnterEvent(self, event):
        function_logger.debug(f"DropTargetLineEdit.dragEnterEvent called")
        if event.mimeData().hasText():
            event.accept()
            self.setStyleSheet("""
                QLineEdit {
                    border: 2px dashed #3498db;
                    background-color: #e8f4fd;
                }
            """)
        else:
            event.ignore()
            
    def dragLeaveEvent(self, event):
        function_logger.debug(f"DropTargetLineEdit.dragLeaveEvent called")
        self.setStyleSheet("")
        
    def dropEvent(self, event):
        function_logger.debug(f"DropTargetLineEdit.dropEvent called")
        if event.mimeData().hasText():
            charset = event.mimeData().text()
            current_text = self.text()
            
            # 检查是否已经包含这些字符，避免重复
            new_chars = ""
            for char in charset:
                if char not in current_text:
                    new_chars += char
                    
            if new_chars:
                self.setText(current_text + new_chars)
                
            event.accept()
        else:
            event.ignore()
            
        self.setStyleSheet("")

class Config:
    """配置常量"""
    CONFIG_FILE = 'hashcat_config.json'
    MASK_CONFIG_FILE = 'mask_generator_config.json'
    DEFAULT_JOHN_PATH = r"JohnTheRipper-v1.8.0.12-jumbo-1-bleeding-e6214ceab--2018-02-07--Win-x64\run"
    DEFAULT_HASHCAT_PATH = "hashcat-6.2.6"
    DEFAULT_STATUS_TIMER = '5'
    DEFAULT_TIMEOUT = 30
    
    # 可执行文件名
    JOHN_EXE = 'john.exe'
    HASHCAT_EXE = 'hashcat.exe'
    ZIP2JOHN_EXE = 'zip2john.exe'
    RAR2JOHN_EXE = 'rar2john.exe'
    SEVENZ2JOHN_EXE = '7z2john.exe'
    SEVENZ2JOHN_PL = '7z2john.pl'
    OFFICE2JOHN_PY = 'office2john.py'
    PDF2JOHN_PL = 'pdf2john.pl'
    PDF2JOHN_PY = 'pdf2john.py'
    LIBREOFFICE2JOHN_PY = 'libreoffice2john.py'
    
    # 新增的2john工具
    KEEPASS2JOHN_EXE = 'keepass2john.exe'
    BITCOIN2JOHN_PY = 'bitcoin2john.py'
    ETHEREUM2JOHN_PY = 'ethereum2john.py'
    IWORK2JOHN_PY = 'iwork2john.py'
    TRUECRYPT2JOHN_PY = 'truecrypt2john.py'
    AXCRYPT2JOHN_PY = 'axcrypt2john.py'
    ITUNES_BACKUP2JOHN_PL = 'itunes_backup2john.pl'
    KEYCHAIN2JOHN_PY = 'keychain2john.py'
    LUKS2JOHN_PY = 'luks2john.py'
    DMG2JOHN_PY = 'dmg2john.py'
    PWSAFE2JOHN_PY = 'pwsafe2john.py'
    ENPASS2JOHN_PY = 'enpass2john.py'
    BITWARDEN2JOHN_PY = 'bitwarden2john.py'
    MULTIBIT2JOHN_PY = 'multibit2john.py'
    ELECTRUM2JOHN_PY = 'electrum2john.py'
    LOTUS2JOHN_PY = 'lotus2john.py'
    MOZILLA2JOHN_PY = 'mozilla2john.py'
    FILEZILLA2JOHN_PY = 'filezilla2john.py'
    ENCFS2JOHN_PY = 'encfs2john.py'
    STAROFFICE2JOHN_PY = 'staroffice2john.py'
    
    # hashcat工具
    AESCRYPT2HASHCAT_PL = 'aescrypt2hashcat.pl'
    BITWARDEN2HASHCAT_PY = 'bitwarden2hashcat.py'
    CRYPTOLOOP2HASHCAT_PY = 'cryptoloop2hashcat.py'
    EXODUS2HASHCAT_PY = 'exodus2hashcat.py'
    LUKS2HASHCAT_PY = 'luks2hashcat.py'
    METAMASK2HASHCAT_PY = 'metamask2hashcat.py'
    MOZILLA2HASHCAT_PY = 'mozilla2hashcat.py'
    RADMIN3_TO_HASHCAT_PL = 'radmin3_to_hashcat.pl'
    SECURENOTES2HASHCAT_PL = 'securenotes2hashcat.pl'
    SQLCIPHER2HASHCAT_PL = 'sqlcipher2hashcat.pl'
    TRUECRYPT2HASHCAT_PY = 'truecrypt2hashcat.py'
    VERACRYPT2HASHCAT_PY = 'veracrypt2hashcat.py'
    VIRTUALBOX2HASHCAT_PY = 'virtualbox2hashcat.py'
    VMWAREVMX2HASHCAT_PY = 'vmwarevmx2hashcat.py'
    
class ErrorHandler:
    """统一错误处理类"""
    
    @staticmethod
    def handle_file_error(operation: str, error: Exception) -> str:
        """处理文件操作错误"""
        function_logger.debug(f"ErrorHandler.handle_file_error called with operation='{operation}', error='{error}'")
        if isinstance(error, FileNotFoundError):
            return f"{operation}失败: 文件未找到"
        elif isinstance(error, PermissionError):
            return f"{operation}失败: 权限不足，请以管理员身份运行"
        elif isinstance(error, subprocess.TimeoutExpired):
            return f"{operation}失败: 操作超时"
        else:
            return f"{operation}失败: {str(error)}"
    
    @staticmethod
    def handle_subprocess_error(operation: str, result: subprocess.CompletedProcess) -> str:
        """处理子进程错误"""
        function_logger.debug(f"ErrorHandler.handle_subprocess_error called with operation='{operation}', returncode={result.returncode}")
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "未知错误"
            return f"{operation}失败: {error_msg}"
        return ""

class HashDetector:
    """哈希类型检测器"""
    
    @staticmethod
    def detect_office_hash_type(hash_value: str) -> str:
        """检测Office文档哈希类型"""
        function_logger.debug(f"HashDetector.detect_office_hash_type called with hash_value length={len(hash_value)}")
        if '$office$' in hash_value:
            if '$office$2007$' in hash_value:
                return HashTypes.OFFICE_2007
            elif '$office$2010$' in hash_value:
                return HashTypes.OFFICE_2010
            elif '$office$2013$' in hash_value:
                return HashTypes.OFFICE_2013
            else:
                return HashTypes.OFFICE_2007  # 默认
        elif '$oldoffice$' in hash_value:
            if '$oldoffice$0$' in hash_value or '$oldoffice$1$' in hash_value:
                return HashTypes.OFFICE_OLD_MD5
            elif '$oldoffice$3$' in hash_value or '$oldoffice$4$' in hash_value:
                return HashTypes.OFFICE_OLD_SHA1
            else:
                return HashTypes.OFFICE_OLD_MD5  # 默认
        else:
            return HashTypes.OFFICE_2007  # 默认
    
    @staticmethod
    def detect_pdf_hash_type(hash_value: str) -> str:
        """检测PDF哈希类型"""
        function_logger.debug(f"HashDetector.detect_pdf_hash_type called with hash_value length={len(hash_value)}")
        if '$pdf$1$' in hash_value:
            return HashTypes.PDF_1_1_1_3
        elif '$pdf$2$' in hash_value:
            return HashTypes.PDF_1_4_1_6
        elif '$pdf$3$' in hash_value:
            return HashTypes.PDF_1_7_L3
        elif '$pdf$4$' in hash_value:
            return HashTypes.PDF_1_7_L8
        else:
            return HashTypes.PDF_1_4_1_6  # 默认
    
    @staticmethod
    def detect_rar_hash_type(hash_value: str) -> str:
        """检测RAR哈希类型"""
        function_logger.debug(f"HashDetector.detect_rar_hash_type called with hash_value length={len(hash_value)}")
        if hash_value.startswith('$rar5$'):
            return HashTypes.RAR5
        elif hash_value.startswith('$RAR3$'):
            if '$RAR3$*0*' in hash_value:
                return HashTypes.RAR3_HP
            elif '$RAR3$*1*' in hash_value:
                return HashTypes.RAR3_P_UNCOMPRESSED
            else:
                return HashTypes.RAR3_HP  # 默认
        else:
            return HashTypes.RAR3_HP  # 默认
    
    @staticmethod
    def detect_zip_hash_type(hash_value: str) -> str:
        """检测ZIP哈希类型"""
        function_logger.debug(f"HashDetector.detect_zip_hash_type called with hash_value length={len(hash_value)}")
        if hash_value.startswith('$pkzip2$'):
            return HashTypes.PKZIP
        else:
            return HashTypes.WINZIP
    
    @staticmethod
    def detect_odf_hash_type(hash_value: str) -> str:
        """检测OpenDocument哈希类型"""
        function_logger.debug(f"HashDetector.detect_odf_hash_type called with hash_value length={len(hash_value)}")
        if '$odf$' in hash_value:
            if 'sha256' in hash_value.lower():
                return HashTypes.ODF_1_2
            else:
                return HashTypes.ODF_1_1
        else:
            return HashTypes.ODF_1_2  # 默认
    
    @staticmethod
    def detect_keepass_hash_type(hash_value: str) -> str:
        """检测KeePass哈希类型"""
        function_logger.debug(f"HashDetector.detect_keepass_hash_type called with hash_value length={len(hash_value)}")
        if '$keepass$' in hash_value:
            return HashTypes.KEEPASS_2_X
        return HashTypes.KEEPASS_2_X  # 默认
    
    @staticmethod
    def detect_bitcoin_hash_type(hash_value: str) -> str:
        """检测Bitcoin钱包哈希类型"""
        function_logger.debug(f"HashDetector.detect_bitcoin_hash_type called with hash_value length={len(hash_value)}")
        if '$bitcoin$' in hash_value:
            return HashTypes.BITCOIN_CORE
        return HashTypes.BITCOIN_CORE  # 默认
    
    @staticmethod
    def detect_ethereum_hash_type(hash_value: str) -> str:
        """检测Ethereum钱包哈希类型"""
        function_logger.debug(f"HashDetector.detect_ethereum_hash_type called with hash_value length={len(hash_value)}")
        if '$ethereum$p' in hash_value:
            return HashTypes.ETHEREUM_PRESALE
        elif '$ethereum$' in hash_value:
            return HashTypes.ETHEREUM_WALLET
        return HashTypes.ETHEREUM_WALLET  # 默认
    
    @staticmethod
    def detect_iwork_hash_type(hash_value: str) -> str:
        """检测iWork文档哈希类型"""
        function_logger.debug(f"HashDetector.detect_iwork_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.APPLE_IWORK
    
    @staticmethod
    def detect_truecrypt_hash_type(hash_value: str) -> str:
        """检测TrueCrypt/VeraCrypt哈希类型"""
        function_logger.debug(f"HashDetector.detect_truecrypt_hash_type called with hash_value length={len(hash_value)}")
        if 'truecrypt_RIPEMD_160' in hash_value:
            return HashTypes.TRUECRYPT_RIPEMD160
        elif 'truecrypt_SHA_512' in hash_value:
            return HashTypes.TRUECRYPT_SHA512
        elif 'truecrypt_WHIRLPOOL' in hash_value:
            return HashTypes.TRUECRYPT_WHIRLPOOL
        elif '$veracrypt$' in hash_value:
            return HashTypes.VERACRYPT_SHA512
        return HashTypes.TRUECRYPT_RIPEMD160  # 默认
    
    @staticmethod
    def detect_veracrypt_hash_type(hash_value: str) -> str:
        """检测VeraCrypt哈希类型"""
        function_logger.debug(f"HashDetector.detect_veracrypt_hash_type called with hash_value length={len(hash_value)}")
        if '$veracrypt$' in hash_value:
            # 根据哈希值长度和内容判断具体的VeraCrypt类型
            # 默认返回SHA512类型，这是最常见的VeraCrypt类型
            return HashTypes.VERACRYPT_SHA512
        return HashTypes.VERACRYPT_SHA512  # 默认
    
    @staticmethod
    def detect_axcrypt_hash_type(hash_value: str) -> str:
        """检测AxCrypt哈希类型"""
        function_logger.debug(f"HashDetector.detect_axcrypt_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.AXCRYPT
    
    @staticmethod
    def detect_itunes_hash_type(hash_value: str) -> str:
        """检测iTunes备份哈希类型"""
        function_logger.debug(f"HashDetector.detect_itunes_hash_type called with hash_value length={len(hash_value)}")
        if '$itunes_backup$*10*' in hash_value:
            return HashTypes.ITUNES_BACKUP_10
        elif '$itunes_backup$*9*' in hash_value:
            return HashTypes.ITUNES_BACKUP_9
        return HashTypes.ITUNES_BACKUP_10  # 默认
    
    @staticmethod
    def detect_luks_hash_type(hash_value: str) -> str:
        """检测LUKS哈希类型"""
        function_logger.debug(f"HashDetector.detect_luks_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.LUKS
    
    @staticmethod
    def detect_dmg_hash_type(hash_value: str) -> str:
        """检测DMG哈希类型"""
        function_logger.debug(f"HashDetector.detect_dmg_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.DMG
    
    @staticmethod
    def detect_pwsafe_hash_type(hash_value: str) -> str:
        """检测Password Safe哈希类型"""
        function_logger.debug(f"HashDetector.detect_pwsafe_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.PWSAFE_V3
    
    @staticmethod
    def detect_enpass_hash_type(hash_value: str) -> str:
        """检测Enpass哈希类型"""
        function_logger.debug(f"HashDetector.detect_enpass_hash_type called with hash_value length={len(hash_value)}")
        if 'enpass6' in hash_value.lower():
            return HashTypes.ENPASS_6
        return HashTypes.ENPASS_5  # 默认
    
    @staticmethod
    def detect_bitwarden_hash_type(hash_value: str) -> str:
        """检测Bitwarden哈希类型"""
        function_logger.debug(f"HashDetector.detect_bitwarden_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.BITWARDEN
    
    @staticmethod
    def detect_multibit_hash_type(hash_value: str) -> str:
        """检测MultiBit钱包哈希类型"""
        function_logger.debug(f"HashDetector.detect_multibit_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.MULTIBIT_HD
    
    @staticmethod
    def detect_electrum_hash_type(hash_value: str) -> str:
        """检测Electrum钱包哈希类型"""
        function_logger.debug(f"HashDetector.detect_electrum_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.ELECTRUM_WALLET_NEW
    
    @staticmethod
    def detect_lotus_hash_type(hash_value: str) -> str:
        """检测Lotus Notes哈希类型"""
        function_logger.debug(f"HashDetector.detect_lotus_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.LOTUS_NOTES_DOMINOSEC
    
    @staticmethod
    def detect_mozilla_hash_type(hash_value: str) -> str:
        """检测Mozilla哈希类型"""
        function_logger.debug(f"HashDetector.detect_mozilla_hash_type called with hash_value length={len(hash_value)}")
        if 'key4.db' in hash_value.lower():
            return HashTypes.MOZILLA_KEY4
        return HashTypes.MOZILLA_KEY3  # 默认
    
    @staticmethod
    def detect_filezilla_hash_type(hash_value: str) -> str:
        """检测FileZilla哈希类型"""
        function_logger.debug(f"HashDetector.detect_filezilla_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.FILEZILLA_SERVER
    
    @staticmethod
    def detect_encfs_hash_type(hash_value: str) -> str:
        """检测EncFS哈希类型"""
        function_logger.debug(f"HashDetector.detect_encfs_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.ENCFS
    
    @staticmethod
    def detect_staroffice_hash_type(hash_value: str) -> str:
        """检测StarOffice哈希类型"""
        function_logger.debug(f"HashDetector.detect_staroffice_hash_type called with hash_value length={len(hash_value)}")
        return HashTypes.STAROFFICE
    
    @classmethod
    def detect_hash_type_by_file_ext(cls, file_ext: str, hash_value: str) -> str:
        """根据文件扩展名和哈希值检测哈希类型"""
        function_logger.debug(f"HashDetector.detect_hash_type_by_file_ext called with file_ext='{file_ext}', hash_value length={len(hash_value)}")
        file_ext = file_ext.lower()
        
        # 压缩文件
        if file_ext == '.zip':
            return cls.detect_zip_hash_type(hash_value)
        elif file_ext == '.rar':
            return cls.detect_rar_hash_type(hash_value)
        elif file_ext == '.7z':
            return HashTypes.SEVEN_ZIP
        
        # Office文档
        elif file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            return cls.detect_office_hash_type(hash_value)
        elif file_ext == '.pdf':
            return cls.detect_pdf_hash_type(hash_value)
        elif file_ext in ['.odt', '.ods', '.odp', '.odg', '.odf']:
            return cls.detect_odf_hash_type(hash_value)
        elif file_ext in ['.sxc', '.sxw', '.sxi', '.sxd']:
            return cls.detect_staroffice_hash_type(hash_value)
        
        # 密码管理器
        elif file_ext in ['.kdbx', '.kdb']:
            return cls.detect_keepass_hash_type(hash_value)
        elif file_ext == '.psafe3':
            return cls.detect_pwsafe_hash_type(hash_value)
        elif file_ext in ['.enpassdb', '.walletx']:
            return cls.detect_enpass_hash_type(hash_value)
        elif file_ext == '.db':
            return cls.detect_bitwarden_hash_type(hash_value)
        
        # 加密货币钱包
        elif file_ext in ['.dat', '.wallet']:
            return cls.detect_bitcoin_hash_type(hash_value)
        elif file_ext in ['.json', '.keystore']:
            return cls.detect_ethereum_hash_type(hash_value)
        elif file_ext == '.multibit':
            return cls.detect_multibit_hash_type(hash_value)
        elif file_ext == '.electrum':
            return cls.detect_electrum_hash_type(hash_value)
        
        # Apple相关
        elif file_ext in ['.key', '.numbers', '.pages']:
            return cls.detect_iwork_hash_type(hash_value)
        elif file_ext == '.plist':
            return cls.detect_itunes_hash_type(hash_value)
        elif file_ext == '.keychain':
            return HashTypes.APPLE_KEYCHAIN
        elif file_ext == '.dmg':
            return cls.detect_dmg_hash_type(hash_value)
        
        # 磁盘加密
        elif file_ext in ['.tc', '.hc']:
            return cls.detect_truecrypt_hash_type(hash_value)
        elif file_ext == '.vc':
            return cls.detect_veracrypt_hash_type(hash_value)
        elif file_ext in ['.luks', '.img']:
            return cls.detect_luks_hash_type(hash_value)
        
        # 文件加密
        elif file_ext == '.axx':
            return cls.detect_axcrypt_hash_type(hash_value)
        elif file_ext == '.encfs6.xml':
            return cls.detect_encfs_hash_type(hash_value)
        
        # 应用程序
        elif file_ext in ['.id', '.nsf']:
            return cls.detect_lotus_hash_type(hash_value)
        elif file_ext in ['.key3.db', '.key4.db']:
            return cls.detect_mozilla_hash_type(hash_value)
        elif file_ext == '.xml':
            return cls.detect_filezilla_hash_type(hash_value)
        
        else:
            return HashTypes.MD5  # 默认

class DeviceCache:
    """设备列表缓存"""
    _cache: Optional[List[str]] = None
    _cache_time: float = 0
    _cache_duration: float = 300  # 5分钟缓存
    
    @classmethod
    def get_devices(cls, hashcat_path: str) -> List[str]:
        """获取设备列表（带缓存）"""
        function_logger.debug(f"DeviceCache.get_devices called with hashcat_path='{hashcat_path}'")
        current_time = time.time()
        if (cls._cache is None or 
            current_time - cls._cache_time > cls._cache_duration):
            cls._refresh_cache(hashcat_path)
        return cls._cache or []
    
    @classmethod
    def _refresh_cache(cls, hashcat_path: str) -> None:
        """刷新设备缓存"""
        function_logger.debug(f"DeviceCache._refresh_cache called with hashcat_path='{hashcat_path}'")
        try:
            # 实现设备列表获取逻辑
            cls._cache = []  # 这里应该实现实际的设备获取逻辑
            cls._cache_time = time.time()
        except Exception:
            cls._cache = []
    
    @classmethod
    def clear_cache(cls) -> None:
        """清除缓存"""
        function_logger.debug("DeviceCache.clear_cache called")
        cls._cache = None
        cls._cache_time = 0

class MaskGeneratorDialog(QDialog):
    """掩码生成器对话框"""
    
    def __init__(self, parent=None):
        function_logger.debug(f"MaskGeneratorDialog.__init__ called with parent={parent}")
        super().__init__(parent)
        self.setWindowTitle("掩码生成器")
        self.setModal(True)
        self.resize(500, 400)
        # 移除帮助按钮
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.parent_window = parent
        # 掩码生成器配置文件
        self.mask_config_file = 'mask_generator_config.json'
        self.setup_ui()
        # 先初始化当前掩码
        self.load_current_mask()
        # 然后加载掩码生成器配置（会覆盖当前掩码的设置）
        self.load_mask_generator_config()
    
    def setup_ui(self):
        function_logger.debug("MaskGeneratorDialog.setup_ui called")
        layout = QVBoxLayout(self)
        
        # 掩码长度设置
        length_group = QGroupBox("掩码长度")
        length_layout = QHBoxLayout(length_group)
        
        length_layout.addWidget(QLabel("长度:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(1, 20)
        self.length_spin.setValue(8)
        self.length_spin.valueChanged.connect(self.update_mask_preview)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        
        layout.addWidget(length_group)
        
        # 字符类型选择
        char_group = QGroupBox("字符类型")
        char_layout = QGridLayout(char_group)
        
        self.lowercase_check = QCheckBox("小写字母 (a-z)")
        self.lowercase_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.lowercase_check, 0, 0)
        
        self.uppercase_check = QCheckBox("大写字母 (A-Z)")
        self.uppercase_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.uppercase_check, 0, 1)
        
        self.digits_check = QCheckBox("数字 (0-9)")
        self.digits_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.digits_check, 1, 0)
        
        self.symbols_check = QCheckBox("符号 (!@#$...)")
        self.symbols_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.symbols_check, 1, 1)
        
        self.all_check = QCheckBox("所有字符 (?a)")
        self.all_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.all_check, 2, 0)
        
        # 自定义字符集复选框
        self.custom1_check = QCheckBox("自定义字符集1 (?1)")
        self.custom1_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.custom1_check, 3, 0)
        
        self.custom2_check = QCheckBox("自定义字符集2 (?2)")
        self.custom2_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.custom2_check, 3, 1)
        
        self.custom3_check = QCheckBox("自定义字符集3 (?3)")
        self.custom3_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.custom3_check, 4, 0)
        
        self.custom4_check = QCheckBox("自定义字符集4 (?4)")
        self.custom4_check.stateChanged.connect(self.update_mask_preview)
        char_layout.addWidget(self.custom4_check, 4, 1)
        
        layout.addWidget(char_group)
        
        # 自定义字符集输入
        custom_group = QGroupBox("自定义字符集（可拖拽）")
        custom_layout = QGridLayout(custom_group)
        
        # 创建可拖拽的标签
        drag_label = QLabel("可拖拽的字符类型:")
        custom_layout.addWidget(drag_label, 0, 0, 1, 3)
        
        self.lowercase_label = DraggableLabel("小写字母 (a-z)", "abcdefghijklmnopqrstuvwxyz")
        custom_layout.addWidget(self.lowercase_label, 1, 0)
        
        self.uppercase_label = DraggableLabel("大写字母 (A-Z)", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        custom_layout.addWidget(self.uppercase_label, 1, 1)
        
        self.digits_label = DraggableLabel("数字 (0-9)", "0123456789")
        custom_layout.addWidget(self.digits_label, 2, 0)
        
        self.symbols_label = DraggableLabel("符号 (!@#$...)", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
        custom_layout.addWidget(self.symbols_label, 2, 1)
        
        # 自定义字符集1
        custom_layout.addWidget(QLabel("-1:"), 3, 0)
        self.charset1_edit = DropTargetLineEdit()
        self.charset1_edit.setPlaceholderText("例如: abcdef0123456789 (可拖拽字符类型到此处)")
        self.charset1_edit.textChanged.connect(self.on_custom_charset_changed)
        self.charset1_edit.charset_number = 1
        custom_layout.addWidget(self.charset1_edit, 3, 1)
        
        # 清空按钮1
        self.clear1_btn = QPushButton("清空")
        self.clear1_btn.setMaximumWidth(50)
        self.clear1_btn.clicked.connect(lambda: self.clear_charset(1))
        custom_layout.addWidget(self.clear1_btn, 3, 2)
        
        # 自定义字符集2
        custom_layout.addWidget(QLabel("-2:"), 4, 0)
        self.charset2_edit = DropTargetLineEdit()
        self.charset2_edit.setPlaceholderText("例如: ABCDEF (可拖拽字符类型到此处)")
        self.charset2_edit.textChanged.connect(self.on_custom_charset_changed)
        self.charset2_edit.charset_number = 2
        custom_layout.addWidget(self.charset2_edit, 4, 1)
        
        # 清空按钮2
        self.clear2_btn = QPushButton("清空")
        self.clear2_btn.setMaximumWidth(50)
        self.clear2_btn.clicked.connect(lambda: self.clear_charset(2))
        custom_layout.addWidget(self.clear2_btn, 4, 2)
        
        # 自定义字符集3
        custom_layout.addWidget(QLabel("-3:"), 5, 0)
        self.charset3_edit = DropTargetLineEdit()
        self.charset3_edit.setPlaceholderText("例如: !@#$%^&* (可拖拽字符类型到此处)")
        self.charset3_edit.textChanged.connect(self.on_custom_charset_changed)
        self.charset3_edit.charset_number = 3
        custom_layout.addWidget(self.charset3_edit, 5, 1)
        
        # 清空按钮3
        self.clear3_btn = QPushButton("清空")
        self.clear3_btn.setMaximumWidth(50)
        self.clear3_btn.clicked.connect(lambda: self.clear_charset(3))
        custom_layout.addWidget(self.clear3_btn, 5, 2)
        
        # 自定义字符集4
        custom_layout.addWidget(QLabel("-4:"), 6, 0)
        self.charset4_edit = DropTargetLineEdit()
        self.charset4_edit.setPlaceholderText("例如: 0123456789 (可拖拽字符类型到此处)")
        self.charset4_edit.textChanged.connect(self.on_custom_charset_changed)
        self.charset4_edit.charset_number = 4
        custom_layout.addWidget(self.charset4_edit, 6, 1)
        
        # 清空按钮4
        self.clear4_btn = QPushButton("清空")
        self.clear4_btn.setMaximumWidth(50)
        self.clear4_btn.clicked.connect(lambda: self.clear_charset(4))
        custom_layout.addWidget(self.clear4_btn, 6, 2)
        
        # 自定义字符集说明
        custom_info = QLabel("在掩码中使用 ?1 ?2 ?3 ?4 来引用自定义字符集")
        custom_info.setStyleSheet("color: gray; font-size: 12px;")
        custom_layout.addWidget(custom_info, 7, 0, 1, 3)
        
        layout.addWidget(custom_group)
        
        # 掩码预览
        preview_group = QGroupBox("掩码预览")
        preview_layout = QVBoxLayout(preview_group)
        
        self.mask_preview = QLineEdit()
        self.mask_preview.setFont(QFont("Consolas", 12))
        self.mask_preview.textChanged.connect(self.on_mask_edited)
        preview_layout.addWidget(self.mask_preview)
        
        # 预计候选数量
        self.candidates_label = QLabel("预计候选数量: 计算中...")
        self.candidates_label.setStyleSheet("color: blue; font-weight: bold;")
        preview_layout.addWidget(self.candidates_label)
        
        layout.addWidget(preview_group)
        
        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.button(QDialogButtonBox.Ok).setText("确定")
        button_box.button(QDialogButtonBox.Cancel).setText("取消")
        button_box.accepted.connect(self.on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # 默认选中所有字符
        self.all_check.setChecked(True)
        
        # 同步主界面的自定义字符集内容
        self.sync_custom_charsets_from_parent()
        
        # 更新自定义字符集状态
        self.update_custom_charset_status()
        
        # 初始化掩码预览
        self.update_mask_preview()
        
        # 记录当前焦点的字符集输入框

    
    def sync_custom_charsets_from_parent(self):
        """从主界面同步自定义字符集内容"""
        function_logger.debug("MaskGeneratorDialog.sync_custom_charsets_from_parent called")
        if self.parent_window:
            self.charset1_edit.setText(self.parent_window.charset1_edit.text())
            self.charset2_edit.setText(self.parent_window.charset2_edit.text())
            self.charset3_edit.setText(self.parent_window.charset3_edit.text())
            self.charset4_edit.setText(self.parent_window.charset4_edit.text())
    
    def on_custom_charset_changed(self):
        """处理自定义字符集输入框变化"""
        function_logger.debug("MaskGeneratorDialog.on_custom_charset_changed called")
        # 同步到主界面
        if self.parent_window:
            self.parent_window.charset1_edit.setText(self.charset1_edit.text())
            self.parent_window.charset2_edit.setText(self.charset2_edit.text())
            self.parent_window.charset3_edit.setText(self.charset3_edit.text())
            self.parent_window.charset4_edit.setText(self.charset4_edit.text())
        
        # 更新复选框状态
        self.update_custom_charset_status()
        
        # 更新掩码预览
        self.update_mask_preview()
    
    def update_custom_charset_status(self):
        """更新自定义字符集复选框的状态"""
        function_logger.debug("MaskGeneratorDialog.update_custom_charset_status called")
        # 检查掩码生成器内的自定义字符集输入框是否有内容
        charset1_enabled = bool(self.charset1_edit.text().strip())
        charset2_enabled = bool(self.charset2_edit.text().strip())
        charset3_enabled = bool(self.charset3_edit.text().strip())
        charset4_enabled = bool(self.charset4_edit.text().strip())
        
        # 设置复选框的启用状态
        self.custom1_check.setEnabled(charset1_enabled)
        self.custom2_check.setEnabled(charset2_enabled)
        self.custom3_check.setEnabled(charset3_enabled)
        self.custom4_check.setEnabled(charset4_enabled)
        
        # 如果禁用了，取消选中
        if not charset1_enabled:
            self.custom1_check.setChecked(False)
        if not charset2_enabled:
            self.custom2_check.setChecked(False)
        if not charset3_enabled:
            self.custom3_check.setChecked(False)
        if not charset4_enabled:
            self.custom4_check.setChecked(False)
    
    def on_all_check_changed(self, state):
        """处理全选复选框状态变化"""
        function_logger.debug(f"MaskGeneratorDialog.on_all_check_changed called with state={state}")
        if state == 2:  # 选中
            self.lowercase_check.setChecked(False)
            self.uppercase_check.setChecked(False)
            self.digits_check.setChecked(False)
            self.symbols_check.setChecked(False)
            self.custom1_check.setChecked(False)
            self.custom2_check.setChecked(False)
            self.custom3_check.setChecked(False)
            self.custom4_check.setChecked(False)
        self.update_mask_preview()
    
    def update_mask_preview(self):
        """更新掩码预览"""
        function_logger.debug("MaskGeneratorDialog.update_mask_preview called")
        length = self.length_spin.value()
        
        if self.all_check.isChecked():
            mask = "?a" * length
        else:
            # 根据选中的字符类型生成掩码
            char_types = []
            if self.lowercase_check.isChecked():
                char_types.append("?l")
            if self.uppercase_check.isChecked():
                char_types.append("?u")
            if self.digits_check.isChecked():
                char_types.append("?d")
            if self.symbols_check.isChecked():
                char_types.append("?s")
            if self.custom1_check.isChecked() and self.custom1_check.isEnabled():
                char_types.append("?1")
            if self.custom2_check.isChecked() and self.custom2_check.isEnabled():
                char_types.append("?2")
            if self.custom3_check.isChecked() and self.custom3_check.isEnabled():
                char_types.append("?3")
            if self.custom4_check.isChecked() and self.custom4_check.isEnabled():
                char_types.append("?4")
            
            if not char_types:
                mask = "?a" * length  # 默认使用全字符
            elif len(char_types) == 1:
                mask = char_types[0] * length
            else:
                # 混合字符类型，交替使用
                mask = ""
                for i in range(length):
                    mask += char_types[i % len(char_types)]
        
        self.mask_preview.setText(mask)
        self.calculate_candidates(mask)
    
    def on_mask_edited(self):
        """处理掩码手动编辑"""
        function_logger.debug("MaskGeneratorDialog.on_mask_edited called")
        mask = self.mask_preview.text()
        self.calculate_candidates(mask)
    
    def calculate_candidates(self, mask):
        """计算候选数量"""
        function_logger.debug(f"MaskGeneratorDialog.calculate_candidates called with mask='{mask}'")
        try:
            total = 1
            i = 0
            while i < len(mask):
                if mask[i] == '?' and i + 1 < len(mask):
                    char_type = mask[i + 1]
                    if char_type == 'l':  # 小写字母
                        total *= 26
                    elif char_type == 'u':  # 大写字母
                        total *= 26
                    elif char_type == 'd':  # 数字
                        total *= 10
                    elif char_type == 's':  # 符号
                        total *= 33  # 常见符号数量
                    elif char_type == 'a':  # 所有字符
                        total *= 95  # 可打印ASCII字符
                    elif char_type in '1234':  # 自定义字符集
                        # 根据实际的自定义字符集长度计算
                        if char_type == '1' and self.charset1_edit.text().strip():
                            total *= len(self.charset1_edit.text().strip())
                        elif char_type == '2' and self.charset2_edit.text().strip():
                            total *= len(self.charset2_edit.text().strip())
                        elif char_type == '3' and self.charset3_edit.text().strip():
                            total *= len(self.charset3_edit.text().strip())
                        elif char_type == '4' and self.charset4_edit.text().strip():
                            total *= len(self.charset4_edit.text().strip())
                        else:
                            total *= 10  # 默认值
                    i += 2
                else:
                    i += 1
            
            if total > 1e12:
                self.candidates_label.setText(f"预计候选数量: {total:.2e} (非常大!)")
                self.candidates_label.setStyleSheet("color: red; font-weight: bold;")
            elif total > 1e9:
                self.candidates_label.setText(f"预计候选数量: {total:.2e} (很大)")
                self.candidates_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.candidates_label.setText(f"预计候选数量: {total:,}")
                self.candidates_label.setStyleSheet("color: blue; font-weight: bold;")
        except:
            self.candidates_label.setText("预计候选数量: 计算错误")
            self.candidates_label.setStyleSheet("color: red; font-weight: bold;")
    
    def load_current_mask(self):
        """从主界面加载当前掩码并解析设置"""
        function_logger.debug("MaskGeneratorDialog.load_current_mask called")
        if self.parent_window and hasattr(self.parent_window, 'mask_edit'):
            current_mask = self.parent_window.mask_edit.text().strip()
            if current_mask:
                # 设置掩码预览
                self.mask_preview.setText(current_mask)
                # 解析掩码并设置相应的选项
                self.parse_and_set_mask(current_mask)
    
    def parse_and_set_mask(self, mask):
        """解析掩码并设置相应的复选框和长度"""
        function_logger.debug(f"MaskGeneratorDialog.parse_and_set_mask called with mask='{mask}'")
        try:
            # 设置掩码长度
            mask_length = len([c for c in mask if c == '?']) // 2 if '?' in mask else len(mask)
            if mask_length > 0:
                self.length_spin.setValue(min(mask_length, 20))
            
            # 分析掩码中的字符类型
            has_lower = '?l' in mask
            has_upper = '?u' in mask
            has_digit = '?d' in mask
            has_symbol = '?s' in mask
            has_all = '?a' in mask
            has_custom1 = '?1' in mask
            has_custom2 = '?2' in mask
            has_custom3 = '?3' in mask
            has_custom4 = '?4' in mask
            
            # 设置复选框状态
            self.lowercase_check.setChecked(has_lower)
            self.uppercase_check.setChecked(has_upper)
            self.digits_check.setChecked(has_digit)
            self.symbols_check.setChecked(has_symbol)
            self.all_check.setChecked(has_all)
            self.custom1_check.setChecked(has_custom1)
            self.custom2_check.setChecked(has_custom2)
            self.custom3_check.setChecked(has_custom3)
            self.custom4_check.setChecked(has_custom4)
            
        except Exception as e:
            # 解析失败时保持默认设置
            pass
    
    def get_mask(self):
        """获取生成的掩码"""
        function_logger.debug("MaskGeneratorDialog.get_mask called")
        return self.mask_preview.text()
    
    def load_mask_generator_config(self):
        """加载掩码生成器配置"""
        function_logger.debug("MaskGeneratorDialog.load_mask_generator_config called")
        try:
            if os.path.exists(self.mask_config_file):
                with open(self.mask_config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                    # 应用配置到界面控件
                    self.length_spin.setValue(config.get('length', 8))
                    self.lowercase_check.setChecked(config.get('lowercase', False))
                    self.uppercase_check.setChecked(config.get('uppercase', False))
                    self.digits_check.setChecked(config.get('digits', False))
                    self.symbols_check.setChecked(config.get('symbols', False))
                    self.all_check.setChecked(config.get('all_chars', True))
                    self.custom1_check.setChecked(config.get('custom1', False))
                    self.custom2_check.setChecked(config.get('custom2', False))
                    self.custom3_check.setChecked(config.get('custom3', False))
                    self.custom4_check.setChecked(config.get('custom4', False))
                    
                    # 应用自定义字符集
                    self.charset1_edit.setText(config.get('charset1', ''))
                    self.charset2_edit.setText(config.get('charset2', ''))
                    self.charset3_edit.setText(config.get('charset3', ''))
                    self.charset4_edit.setText(config.get('charset4', ''))
                    
                    # 应用掩码预览
                    mask_preview = config.get('mask_preview', '')
                    if mask_preview:
                        self.mask_preview.setText(mask_preview)
                    
        except Exception as e:
            print(f"加载掩码生成器配置失败: {e}")
    
    def save_mask_generator_config(self):
        """保存掩码生成器配置"""
        function_logger.debug("MaskGeneratorDialog.save_mask_generator_config called")
        try:
            config = {
                'length': self.length_spin.value(),
                'lowercase': self.lowercase_check.isChecked(),
                'uppercase': self.uppercase_check.isChecked(),
                'digits': self.digits_check.isChecked(),
                'symbols': self.symbols_check.isChecked(),
                'all_chars': self.all_check.isChecked(),
                'custom1': self.custom1_check.isChecked(),
                'custom2': self.custom2_check.isChecked(),
                'custom3': self.custom3_check.isChecked(),
                'custom4': self.custom4_check.isChecked(),
                'charset1': self.charset1_edit.text(),
                'charset2': self.charset2_edit.text(),
                'charset3': self.charset3_edit.text(),
                'charset4': self.charset4_edit.text(),
                'mask_preview': self.mask_preview.text()
            }
            
            with open(self.mask_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
             print(f"保存掩码生成器配置失败: {e}")
    
    def clear_charset(self, charset_num):
        """清空指定的字符集输入框"""
        function_logger.debug(f"MaskGeneratorDialog.clear_charset called with charset_num={charset_num}")
        charset_edit = getattr(self, f'charset{charset_num}_edit')
        charset_edit.clear()
        
        # 如果掩码中包含对应的数字，则替换为?a
        current_mask = self.mask_preview.text()
        if f'?{charset_num}' in current_mask:
            new_mask = current_mask.replace(f'?{charset_num}', '?a')
            self.mask_preview.setText(new_mask)
            self.calculate_candidates(new_mask)
    
    def on_accept(self):
        """处理确定按钮点击事件"""
        function_logger.debug("MaskGeneratorDialog.on_accept called")
        # 保存掩码生成器配置
        self.save_mask_generator_config()
        # 调用父类的accept方法
        self.accept()

class HashcatWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    success_signal = pyqtSignal(str, str)  # hash_part, password_part
    
    def __init__(self, command, working_dir=None):
        function_logger.debug(f"HashcatWorker.__init__ called with command={command}, working_dir={working_dir}")
        super().__init__()
        self.command = command
        self.working_dir = working_dir
        self.process = None
    
    def run(self):
        function_logger.debug("HashcatWorker.run called")
        try:
            # 使用bytes模式避免编码问题
            # Windows下隐藏控制台窗口
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW
            
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,  # 使用bytes模式
                bufsize=0,  # 无缓冲，实时输出
                cwd=self.working_dir,
                creationflags=creation_flags
            )
            
            # 实时读取输出
            while True:
                output = self.process.stdout.readline()
                if output == b'' and self.process.poll() is not None:
                    break
                if output:
                    # 尝试多种编码解码输出
                    line = self._decode_output(output).strip()
                    if line:  # 只发送非空行
                        self.output_signal.emit(line)
            
            # 获取剩余输出
            remaining_output = self.process.stdout.read()
            if remaining_output:
                decoded_output = self._decode_output(remaining_output)
                for line in decoded_output.strip().split('\n'):
                    if line.strip():
                        self.output_signal.emit(line.strip())
            
            self.process.wait()
            self.finished_signal.emit(self.process.returncode)
            
        except Exception as e:
            self.output_signal.emit(f"执行错误: {str(e)}")
            self.finished_signal.emit(-1)
    
    def _decode_output(self, output_bytes):
        """尝试多种编码解码输出"""
        function_logger.debug(f"HashcatWorker._decode_output called with output_bytes length={len(output_bytes)}")
        # 常见编码列表，按优先级排序
        encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                return output_bytes.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        
        # 如果所有编码都失败，使用错误处理模式
        try:
            return output_bytes.decode('utf-8', errors='replace')
        except:
            # 最后的备用方案
            return str(output_bytes, errors='replace')
    
    def stop(self):
        """停止hashcat进程"""
        function_logger.debug("HashcatWorker.stop called")
        if self.process:
            try:
                # 首先尝试优雅地终止进程
                self.process.terminate()
                # 等待进程结束，最多等待0.5秒
                if self.process.poll() is None:
                    import time
                    time.sleep(0.5)
                    # 如果进程仍在运行，强制杀死
                    if self.process.poll() is None:
                        self.process.kill()
            except Exception as e:
                print(f"停止hashcat进程时出错: {str(e)}")
                # 尝试强制杀死进程
                try:
                    self.process.kill()
                except:
                    pass
    
    # send_command方法已移除，hashcat控制功能已禁用

class HashcatGUI(QMainWindow):
    def __init__(self):
        function_logger.debug("HashcatGUI.__init__ called")
        super().__init__()
        self.setWindowTitle("Hashcat GUI - by JIA")
        self.setGeometry(100, 100, 1200, 800)
        
        # 设置窗口图标
        self._setup_window_icon()
        
        # 配置文件路径
        self.config_file = Config.CONFIG_FILE
        
        # 默认路径
        self.john_path = Config.DEFAULT_JOHN_PATH
        self.hashcat_path = Config.DEFAULT_HASHCAT_PATH
        
        # 加载配置
        self.load_config()
        
        # 工作线程
        self.worker: Optional[HashcatWorker] = None
        
        # 状态信息
        self.status_info: Dict[str, str] = {
            'gpu_temp': '--',
            'gpu_util': '--', 
            'speed': '--',
            'progress': '--',
            'eta': '--',
            'elapsed': '--',
            'mask': '--'
        }
        self.is_cracking: bool = False
        
        # 破解成功检测标志
        self.crack_success_detected: bool = False
        
        # 哈希提取缓存 - 避免重复调用xxx2john工具
        # 格式: {文件路径: (哈希值, 哈希类型, 文件修改时间)}
        self.hash_cache: Dict[str, Tuple[str, str, float]] = {}
        
        # 用户手动选择哈希类型的标记
        self._user_selected_hash_type = False
        
        # 初始化界面
        self.init_ui()
        
        # 检查工具
        self.check_tools()
    
    def _setup_window_icon(self) -> None:
        """设置窗口图标"""
        function_logger.debug("HashcatGUI._setup_window_icon called")
        try:
            # 支持打包后的图标路径
            if getattr(sys, 'frozen', False):
                # 打包后的环境
                base_path = sys._MEIPASS
            else:
                # 开发环境
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            icon_path = os.path.join(base_path, "hashcat.ico")
            if os.path.exists(icon_path):
                self.setWindowIcon(QIcon(icon_path))
                print(f"图标设置成功: {icon_path}")
            else:
                print(f"图标文件不存在: {icon_path}")
        except Exception as e:
            print(f"设置图标失败: {e}")
    
    def apply_saved_mask_settings(self):
        """应用保存的掩码设置"""
        function_logger.debug("HashcatGUI.apply_saved_mask_settings called")
        try:
            # 应用掩码
            if hasattr(self, 'saved_mask') and hasattr(self, 'mask_edit'):
                self.mask_edit.setText(self.saved_mask)
            
            # 应用自定义字符集
            if hasattr(self, 'saved_charset1') and hasattr(self, 'charset1_edit'):
                self.charset1_edit.setText(self.saved_charset1)
            if hasattr(self, 'saved_charset2') and hasattr(self, 'charset2_edit'):
                self.charset2_edit.setText(self.saved_charset2)
            if hasattr(self, 'saved_charset3') and hasattr(self, 'charset3_edit'):
                self.charset3_edit.setText(self.saved_charset3)
            if hasattr(self, 'saved_charset4') and hasattr(self, 'charset4_edit'):
                self.charset4_edit.setText(self.saved_charset4)
        except Exception as e:
            print(f"应用掩码设置失败: {e}")
    
    def process_chinese_name(self, name: str) -> List[str]:
        """处理姓名，生成拼音变体（中文转拼音，非中文直接处理）"""
        function_logger.debug(f"HashcatGUI.process_chinese_name called with name='{name}'")
        result = []
        
        # 检查是否包含中文字符
        has_chinese = any('\u4e00' <= char <= '\u9fff' for char in name)
        
        if not has_chinese:
            # 非中文名字的处理
            result.extend([name, name.lower(), name.upper(), name.capitalize()])
            return result
        
        if not PINYIN_AVAILABLE:
            # 如果没有拼音库，对于中文名字只返回空列表
            return []
        
        try:
            # 获取全拼
            full_pinyin = ''.join(lazy_pinyin(name, style=Style.NORMAL))
            if full_pinyin:
                result.extend([
                    full_pinyin.lower(),
                    full_pinyin.upper(), 
                    full_pinyin.capitalize()
                ])
            
            # 获取每个字单独大写首字母的拼音（如：张三 -> ZhangSan）
            char_pinyin_list = lazy_pinyin(name, style=Style.NORMAL)
            if char_pinyin_list:
                capitalized_pinyin = ''.join([pinyin.capitalize() for pinyin in char_pinyin_list])
                if capitalized_pinyin and capitalized_pinyin not in result:
                    result.append(capitalized_pinyin)
            
            # 获取首字母
            initials = ''.join(lazy_pinyin(name, style=Style.FIRST_LETTER))
            if initials:
                result.extend([
                    initials.lower(),
                    initials.upper()
                ])
            
            # 处理姓氏（支持复姓）
            surnames = self.extract_chinese_surname(name)
            for surname in surnames:
                # 姓氏全拼
                surname_pinyin = ''.join(lazy_pinyin(surname, style=Style.NORMAL))
                if surname_pinyin:
                    result.extend([
                        surname_pinyin.lower(),
                        surname_pinyin.upper(),
                        surname_pinyin.capitalize()
                    ])
                
                # 姓氏首字母
                surname_initial = ''.join(lazy_pinyin(surname, style=Style.FIRST_LETTER))
                if surname_initial:
                    result.extend([
                        surname_initial.lower(),
                        surname_initial.upper()
                    ])
        
        except Exception as e:
            function_logger.error(f"处理中文姓名拼音失败: {e}")
        
        # 去重并保持顺序
        seen = set()
        unique_result = []
        for item in result:
            if item and item not in seen:
                seen.add(item)
                unique_result.append(item)
        
        return unique_result
    
    def extract_chinese_surname(self, name: str) -> List[str]:
        """提取中文姓氏（支持复姓）"""
        function_logger.debug(f"HashcatGUI.extract_chinese_surname called with name='{name}'")
        
        # 常见复姓列表
        compound_surnames = [
            '欧阳', '太史', '端木', '上官', '司马', '东方', '独孤', '南宫', '万俟', '闻人',
            '夏侯', '诸葛', '尉迟', '公羊', '赫连', '澹台', '皇甫', '宗政', '濮阳', '公冶',
            '太叔', '申屠', '公孙', '慕容', '仲孙', '钟离', '长孙', '宇文', '司徒', '鲜于',
            '司空', '闾丘', '子车', '亓官', '司寇', '巫马', '公西', '颛孙', '壤驷', '公良',
            '漆雕', '乐正', '宰父', '谷梁', '拓跋', '夹谷', '轩辕', '令狐', '段干', '百里',
            '呼延', '东郭', '南门', '羊舌', '微生', '公户', '公玉', '公仪', '梁丘', '公仲',
            '公上', '公门', '公山', '公坚', '左丘', '公伯', '西门', '公祖', '第五', '公乘',
            '贯丘', '公皙', '南荣', '东里', '东宫', '仲长', '子书', '子桑', '即墨', '达奚',
            '褚师'
        ]
        
        surnames = []
        
        # 检查复姓
        for compound in compound_surnames:
            if name.startswith(compound):
                surnames.append(compound)
                break
        else:
            # 如果没有复姓，取第一个字作为单姓
            if name:
                surnames.append(name[0])
        
        return surnames
    
    def init_ui(self):
        """初始化用户界面"""
        function_logger.debug("HashcatGUI.init_ui called")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建各个标签页
        self.create_main_tab()
        self.create_config_tab()
        self.create_dict_generator_tab()
        self.create_help_tab()
        
        # 连接所有信号（确保所有控件都已创建）
        self.setup_signals()
        
        # 应用保存的掩码设置
        self.apply_saved_mask_settings()
        
        # 初始计算候选数量
        self.calculate_main_candidates()
        
        # 状态栏 - 初始化监控信息显示
        self.status_info = {
            'gpu_temp': '--',
            'gpu_util': '--', 
            'speed': '--',
            'progress': '--',
            'eta': '--'
        }
        self.update_status_bar()
    
    def create_main_tab(self):
        """创建主界面标签页"""
        function_logger.debug("HashcatGUI.create_main_tab called")
        main_widget = QWidget()
        self.tab_widget.addTab(main_widget, "Hash爆破")
        
        layout = QVBoxLayout(main_widget)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # 左侧面板
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # 解密类型选择 - 放在一行
        decrypt_layout = QHBoxLayout()
        decrypt_layout.addWidget(QLabel("解密类型:"))
        
        self.decrypt_type_group = QButtonGroup()
        self.file_radio = QRadioButton("文件解密")
        self.text_radio = QRadioButton("文本解密")
        self.batch_radio = QRadioButton("批量解密")
        self.text_radio.setChecked(True)  # 修改默认选中为文本解密
        
        self.decrypt_type_group.addButton(self.file_radio, 0)
        self.decrypt_type_group.addButton(self.text_radio, 1)
        self.decrypt_type_group.addButton(self.batch_radio, 2)
        
        decrypt_layout.addWidget(self.file_radio)
        decrypt_layout.addWidget(self.text_radio)
        decrypt_layout.addWidget(self.batch_radio)
        decrypt_layout.addStretch()
        
        left_layout.addLayout(decrypt_layout)
        
        # 文件/文本输入区域
        self.input_group = QGroupBox("输入")
        self.input_group.setMinimumWidth(400)
        self.input_layout = QGridLayout(self.input_group)
        self.input_layout.setColumnMinimumWidth(1, 250)  # 设置输入框列的最小宽度
        
        # 文件路径
        self.file_label = QLabel("文件路径:")
        self.file_label.setFixedWidth(80)
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setMinimumWidth(250)
        self.browse_file_btn = QPushButton("浏览")
        self.browse_file_btn.setFixedWidth(60)
        self.browse_file_btn.clicked.connect(self.browse_file)
        
        # 文本哈希
        self.hash_label = QLabel("哈 希 值:")
        self.hash_label.setFixedWidth(80)
        self.hash_edit = QLineEdit()
        self.hash_edit.setMinimumWidth(250)
        
        # 批量哈希文件
        self.batch_label = QLabel("哈希列表:")
        self.batch_label.setFixedWidth(80)
        self.batch_path_edit = QLineEdit()
        self.batch_path_edit.setMinimumWidth(250)
        self.browse_batch_btn = QPushButton("浏览")
        self.browse_batch_btn.setFixedWidth(60)
        self.browse_batch_btn.clicked.connect(self.browse_batch_file)
        
        # 哈希类型
        self.hash_type_label = QLabel("哈希类型:")
        
        # 哈希类型搜索框
        self.hash_type_search = QLineEdit()
        self.hash_type_search.setPlaceholderText("搜索哈希类型...")
        
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.setEditable(False)
        self.hash_type_combo.addItems([
            # Raw Hash
            "0 - MD5",
            "100 - SHA1",
            "900 - MD4",
            "1300 - SHA2-224",
            "1400 - SHA2-256",
            "10800 - SHA2-384",
            "1700 - SHA2-512",
            "17300 - SHA3-224",
            "17400 - SHA3-256",
            "17500 - SHA3-384",
            "17600 - SHA3-512",
            "6000 - RIPEMD-160",
            "600 - BLAKE2b-512",
            "11700 - GOST R 34.11-2012 (Streebog) 256-bit",
            "11800 - GOST R 34.11-2012 (Streebog) 512-bit",
            "6900 - GOST R 34.11-94",
            "5100 - Half MD5",
            "17700 - Keccak-224",
            "17800 - Keccak-256",
            "17900 - Keccak-384",
            "18000 - Keccak-512",
            "6100 - Whirlpool",
            "10100 - SipHash",
            "70 - md5(utf16le($pass))",
            "170 - sha1(utf16le($pass))",
            "1470 - sha256(utf16le($pass))",
            "10870 - sha384(utf16le($pass))",
            "1770 - sha512(utf16le($pass))",
            
            # Raw Hash salted and/or iterated
            "10 - md5($pass.$salt)",
            "20 - md5($salt.$pass)",
            "3800 - md5($salt.$pass.$salt)",
            "3710 - md5($salt.md5($pass))",
            "4110 - md5($salt.md5($pass.$salt))",
            "4010 - md5($salt.md5($salt.$pass))",
            "21300 - md5($salt.sha1($salt.$pass))",
            "40 - md5($salt.utf16le($pass))",
            "2600 - md5(md5($pass))",
            "3910 - md5(md5($pass).md5($salt))",
            "3500 - md5(md5(md5($pass)))",
            "4400 - md5(sha1($pass))",
            "4410 - md5(sha1($pass).$salt)",
            "20900 - md5(sha1($pass).md5($pass).sha1($pass))",
            "21200 - md5(sha1($salt).md5($pass))",
            "4300 - md5(strtoupper(md5($pass)))",
            "30 - md5(utf16le($pass).$salt)",
            "110 - sha1($pass.$salt)",
            "120 - sha1($salt.$pass)",
            "4900 - sha1($salt.$pass.$salt)",
            "4520 - sha1($salt.sha1($pass))",
            "24300 - sha1($salt.sha1($pass.$salt))",
            "140 - sha1($salt.utf16le($pass))",
            "19300 - sha1($salt1.$pass.$salt2)",
            "14400 - sha1(CX)",
            "4700 - sha1(md5($pass))",
            "4710 - sha1(md5($pass).$salt)",
            "21100 - sha1(md5($pass.$salt))",
            "18500 - sha1(md5(md5($pass)))",
            "4500 - sha1(sha1($pass))",
            "4510 - sha1(sha1($pass).$salt)",
            "5000 - sha1(sha1($salt.$pass.$salt))",
            "130 - sha1(utf16le($pass).$salt)",
            "1410 - sha256($pass.$salt)",
            "1420 - sha256($salt.$pass)",
            "22300 - sha256($salt.$pass.$salt)",
            "20720 - sha256($salt.sha256($pass))",
            "21420 - sha256($salt.sha256_bin($pass))",
            "1440 - sha256($salt.utf16le($pass))",
            "20800 - sha256(md5($pass))",
            "20710 - sha256(sha256($pass).$salt)",
            "21400 - sha256(sha256_bin($pass))",
            "1430 - sha256(utf16le($pass).$salt)",
            "10810 - sha384($pass.$salt)",
            "10820 - sha384($salt.$pass)",
            "10840 - sha384($salt.utf16le($pass))",
            "10830 - sha384(utf16le($pass).$salt)",
            "1710 - sha512($pass.$salt)",
            "1720 - sha512($salt.$pass)",
            "1740 - sha512($salt.utf16le($pass))",
            "1730 - sha512(utf16le($pass).$salt)",
            
            # Raw Hash authenticated
            "50 - HMAC-MD5 (key = $pass)",
            "60 - HMAC-MD5 (key = $salt)",
            "150 - HMAC-SHA1 (key = $pass)",
            "160 - HMAC-SHA1 (key = $salt)",
            "1450 - HMAC-SHA256 (key = $pass)",
            "1460 - HMAC-SHA256 (key = $salt)",
            "1750 - HMAC-SHA512 (key = $pass)",
            "1760 - HMAC-SHA512 (key = $salt)",
            "11750 - HMAC-Streebog-256 (key = $pass)",
            "11760 - HMAC-Streebog-256 (key = $salt)",
            "11850 - HMAC-Streebog-512 (key = $pass)",
            "11860 - HMAC-Streebog-512 (key = $salt)",
            "28700 - Amazon AWS4-HMAC-SHA256",
            
            # Raw Checksum
            "11500 - CRC32",
            "27900 - CRC32C",
            "28000 - CRC64Jones",
            "18700 - Java Object hashCode()",
            "25700 - MurmurHash",
            "27800 - MurmurHash3",
            
            # Raw Cipher, Known-plaintext attack
            "14100 - 3DES (PT = $salt, key = $pass)",
            "14000 - DES (PT = $salt, key = $pass)",
            "26401 - AES-128-ECB NOKDF (PT = $salt, key = $pass)",
            "26402 - AES-192-ECB NOKDF (PT = $salt, key = $pass)",
            "26403 - AES-256-ECB NOKDF (PT = $salt, key = $pass)",
            "15400 - ChaCha20",
            "14500 - Linux Kernel Crypto API (2.4)",
            "14900 - Skip32 (PT = $salt, key = $pass)",
            
            # Generic KDF
            "11900 - PBKDF2-HMAC-MD5",
            "12000 - PBKDF2-HMAC-SHA1",
            "10900 - PBKDF2-HMAC-SHA256",
            "12100 - PBKDF2-HMAC-SHA512",
            "8900 - scrypt",
            "400 - phpass",
            
            # Network Protocol
            "16100 - TACACS+",
            "11400 - SIP digest authentication (MD5)",
            "5300 - IKE-PSK MD5",
            "5400 - IKE-PSK SHA1",
            "25100 - SNMPv3 HMAC-MD5-96",
            "25000 - SNMPv3 HMAC-MD5-96/HMAC-SHA1-96",
            "25200 - SNMPv3 HMAC-SHA1-96",
            "26700 - SNMPv3 HMAC-SHA224-128",
            "26800 - SNMPv3 HMAC-SHA256-192",
            "26900 - SNMPv3 HMAC-SHA384-256",
            "27300 - SNMPv3 HMAC-SHA512-384",
            "2500 - WPA-EAPOL-PBKDF2",
            "2501 - WPA-EAPOL-PMK",
            "22000 - WPA-PBKDF2-PMKID+EAPOL",
            "22001 - WPA-PMK-PMKID+EAPOL",
            "16800 - WPA-PMKID-PBKDF2",
            "16801 - WPA-PMKID-PMK",
            "7300 - IPMI2 RAKP HMAC-SHA1",
            "10200 - CRAM-MD5",
            "16500 - JWT (JSON Web Token)",
            "29200 - Radmin3",
            "19600 - Kerberos 5, etype 17, TGS-REP",
            "19800 - Kerberos 5, etype 17, Pre-Auth",
            "28800 - Kerberos 5, etype 17, DB",
            "19700 - Kerberos 5, etype 18, TGS-REP",
            "19900 - Kerberos 5, etype 18, Pre-Auth",
            "28900 - Kerberos 5, etype 18, DB",
            "7500 - Kerberos 5, etype 23, AS-REQ Pre-Auth",
            "13100 - Kerberos 5, etype 23, TGS-REP",
            "18200 - Kerberos 5, etype 23, AS-REP",
            "5500 - NetNTLMv1 / NetNTLMv1+ESS",
            "27000 - NetNTLMv1 / NetNTLMv1+ESS (NT)",
            "5600 - NetNTLMv2",
            "27100 - NetNTLMv2 (NT)",
            "29100 - Flask Session Cookie ($salt.$salt.$pass)",
            "4800 - iSCSI CHAP authentication, MD5(CHAP)",
            
            # Operating System
            "8500 - RACF",
            "6300 - AIX {smd5}",
            "6700 - AIX {ssha1}",
            "6400 - AIX {ssha256}",
            "6500 - AIX {ssha512}",
            "3000 - LM",
            "19000 - QNX /etc/shadow (MD5)",
            "19100 - QNX /etc/shadow (SHA256)",
            "19200 - QNX /etc/shadow (SHA512)",
            "15300 - DPAPI masterkey file v1 (context 1 and 2)",
            "15310 - DPAPI masterkey file v1 (context 3)",
            "15900 - DPAPI masterkey file v2 (context 1 and 2)",
            "15910 - DPAPI masterkey file v2 (context 3)",
            "7200 - GRUB 2",
            "12800 - MS-AzureSync PBKDF2-HMAC-SHA256",
            "12400 - BSDi Crypt, Extended DES",
            "1000 - NTLM",
            "9900 - Radmin2",
            "5800 - Samsung Android Password/PIN",
            "28100 - Windows Hello PIN/Password",
            "13800 - Windows Phone 8+ PIN/password",
            "2410 - Cisco-ASA MD5",
            "9200 - Cisco-IOS $8$ (PBKDF2-SHA256)",
            "9300 - Cisco-IOS $9$ (scrypt)",
            "5700 - Cisco-IOS type 4 (SHA256)",
            "2400 - Cisco-PIX MD5",
            "8100 - Citrix NetScaler (SHA1)",
            "22200 - Citrix NetScaler (SHA512)",
            "1100 - Domain Cached Credentials (DCC), MS Cache",
            "2100 - Domain Cached Credentials 2 (DCC2), MS Cache 2",
            "7000 - FortiGate (FortiOS)",
            "26300 - FortiGate256 (FortiOS256)",
            "125 - ArubaOS",
            "501 - Juniper IVE",
            "22 - Juniper NetScreen/SSG (ScreenOS)",
            "15100 - Juniper/NetBSD sha1crypt",
            "26500 - iPhone passcode (UID key + System Keybag)",
            "122 - macOS v10.4, macOS v10.5, macOS v10.6",
            "1722 - macOS v10.7",
            "7100 - macOS v10.8+ (PBKDF2-SHA512)",
            "3200 - bcrypt $2*$, Blowfish (Unix)",
            "500 - md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)",
            "1500 - descrypt, DES (Unix), Traditional DES",
            "29000 - sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))",
            "7400 - sha256crypt $5$, SHA256 (Unix)",
            "1800 - sha512crypt $6$, SHA512 (Unix)",
            
            # Database Server
            "24600 - SQLCipher",
            "131 - MSSQL (2000)",
            "132 - MSSQL (2005)",
            "1731 - MSSQL (2012, 2014)",
            "24100 - MongoDB ServerKey SCRAM-SHA-1",
            "24200 - MongoDB ServerKey SCRAM-SHA-256",
            "12 - PostgreSQL",
            "11100 - PostgreSQL CRAM (MD5)",
            "28600 - PostgreSQL SCRAM-SHA-256",
            "3100 - Oracle H: Type (Oracle 7+)",
            "112 - Oracle S: Type (Oracle 11+)",
            "12300 - Oracle T: Type (Oracle 12+)",
            "7401 - MySQL $A$ (sha256crypt)",
            "11200 - MySQL CRAM (SHA1)",
            "200 - MySQL323",
            "300 - MySQL4.1/MySQL5",
            "8000 - Sybase ASE",
            
            # FTP, HTTP, SMTP, LDAP Server
            "8300 - DNSSEC (NSEC3)",
            "25900 - KNX IP Secure - Device Authentication Code",
            "16400 - CRAM-MD5 Dovecot",
            "1411 - SSHA-256(Base64), LDAP {SSHA256}",
            "1711 - SSHA-512(Base64), LDAP {SSHA512}",
            "24900 - Dahua Authentication MD5",
            "10901 - RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)",
            "15000 - FileZilla Server >= 0.9.55",
            "12600 - ColdFusion 10+",
            "1600 - Apache $apr1$ MD5, md5apr1, MD5 (APR)",
            "141 - Episerver 6.x < .NET 4",
            "1441 - Episerver 6.x >= .NET 4",
            "1421 - hMailServer",
            "101 - nsldap, SHA-1(Base64), Netscape LDAP SHA",
            "111 - nsldaps, SSHA-1(Base64), Netscape LDAP SSHA",
            
            # Enterprise Application Software (EAS)
            "7700 - SAP CODVN B (BCODE)",
            "7701 - SAP CODVN B (BCODE) from RFC_READ_TABLE",
            "7800 - SAP CODVN F/G (PASSCODE)",
            "7801 - SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE",
            "10300 - SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
            "133 - PeopleSoft",
            "13500 - PeopleSoft PS_TOKEN",
            "21500 - SolarWinds Orion",
            "21501 - SolarWinds Orion v2",
            "24 - SolarWinds Serv-U",
            "8600 - Lotus Notes/Domino 5",
            "8700 - Lotus Notes/Domino 6",
            "9100 - Lotus Notes/Domino 8",
            "26200 - OpenEdge Progress Encode",
            "20600 - Oracle Transportation Management (SHA256)",
            "4711 - Huawei sha1(md5($pass).$salt)",
            "20711 - AuthMe sha256",
            
            # Full-Disk Encryption (FDE)
            "22400 - AES Crypt (SHA256)",
            "27400 - VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)",
            "14600 - LUKS v1 (legacy)",
            "29541 - LUKS v1 RIPEMD-160 + AES",
            "29542 - LUKS v1 RIPEMD-160 + Serpent",
            "29543 - LUKS v1 RIPEMD-160 + Twofish",
            "29511 - LUKS v1 SHA-1 + AES",
            "29512 - LUKS v1 SHA-1 + Serpent",
            "29513 - LUKS v1 SHA-1 + Twofish",
            "29521 - LUKS v1 SHA-256 + AES",
            "29522 - LUKS v1 SHA-256 + Serpent",
            "29523 - LUKS v1 SHA-256 + Twofish",
            "29531 - LUKS v1 SHA-512 + AES",
            "29532 - LUKS v1 SHA-512 + Serpent",
            "29533 - LUKS v1 SHA-512 + Twofish",
            "13711 - VeraCrypt RIPEMD160 + XTS 512 bit (legacy)",
            "13712 - VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)",
            "13713 - VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)",
            "13741 - VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)",
            "13742 - VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)",
            "13743 - VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)",
            "29411 - VeraCrypt RIPEMD160 + XTS 512 bit",
            "29412 - VeraCrypt RIPEMD160 + XTS 1024 bit",
            "29413 - VeraCrypt RIPEMD160 + XTS 1536 bit",
            "29441 - VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode",
            "29442 - VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
            "29443 - VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
            "13751 - VeraCrypt SHA256 + XTS 512 bit (legacy)",
            "13752 - VeraCrypt SHA256 + XTS 1024 bit (legacy)",
            "13753 - VeraCrypt SHA256 + XTS 1536 bit (legacy)",
            "13761 - VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)",
            "13762 - VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)",
            "13763 - VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)",
            "29451 - VeraCrypt SHA256 + XTS 512 bit",
            "29452 - VeraCrypt SHA256 + XTS 1024 bit",
            "29453 - VeraCrypt SHA256 + XTS 1536 bit",
            "29461 - VeraCrypt SHA256 + XTS 512 bit + boot-mode",
            "29462 - VeraCrypt SHA256 + XTS 1024 bit + boot-mode",
            "29463 - VeraCrypt SHA256 + XTS 1536 bit + boot-mode",
            "13721 - VeraCrypt SHA512 + XTS 512 bit (legacy)",
            "13722 - VeraCrypt SHA512 + XTS 1024 bit (legacy)",
            "13723 - VeraCrypt SHA512 + XTS 1536 bit (legacy)",
            "29421 - VeraCrypt SHA512 + XTS 512 bit",
            "29422 - VeraCrypt SHA512 + XTS 1024 bit",
            "29423 - VeraCrypt SHA512 + XTS 1536 bit",
            "13771 - VeraCrypt Streebog-512 + XTS 512 bit (legacy)",
            "13772 - VeraCrypt Streebog-512 + XTS 1024 bit (legacy)",
            "13773 - VeraCrypt Streebog-512 + XTS 1536 bit (legacy)",
            "13781 - VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)",
            "13782 - VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy)",
            "13783 - VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy)",
            "29471 - VeraCrypt Streebog-512 + XTS 512 bit",
            "29472 - VeraCrypt Streebog-512 + XTS 1024 bit",
            "29473 - VeraCrypt Streebog-512 + XTS 1536 bit",
            "29481 - VeraCrypt Streebog-512 + XTS 512 bit + boot-mode",
            "29482 - VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode",
            "29483 - VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode",
            "13731 - VeraCrypt Whirlpool + XTS 512 bit (legacy)",
            "13732 - VeraCrypt Whirlpool + XTS 1024 bit (legacy)",
            "13733 - VeraCrypt Whirlpool + XTS 1536 bit (legacy)",
            "29431 - VeraCrypt Whirlpool + XTS 512 bit",
            "29432 - VeraCrypt Whirlpool + XTS 1024 bit",
            "29433 - VeraCrypt Whirlpool + XTS 1536 bit",
            "23900 - BestCrypt v3 Volume Encryption",
            "16700 - FileVault 2",
            "27500 - VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)",
            "27600 - VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)",
            "20011 - DiskCryptor SHA512 + XTS 512 bit",
            "20012 - DiskCryptor SHA512 + XTS 1024 bit",
            "20013 - DiskCryptor SHA512 + XTS 1536 bit",
            "22100 - BitLocker",
            "12900 - Android FDE (Samsung DEK)",
            "8800 - Android FDE <= 4.3",
            "18300 - Apple File System (APFS)",
            "6211 - TrueCrypt RIPEMD160 + XTS 512 bit (legacy)",
            "6212 - TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)",
            "6213 - TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)",
            "6241 - TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)",
            "6242 - TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)",
            "6243 - TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)",
            "29311 - TrueCrypt RIPEMD160 + XTS 512 bit",
            "29312 - TrueCrypt RIPEMD160 + XTS 1024 bit",
            "29313 - TrueCrypt RIPEMD160 + XTS 1536 bit",
            "29341 - TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode",
            "29342 - TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
            "29343 - TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
            "6221 - TrueCrypt SHA512 + XTS 512 bit (legacy)",
            "6222 - TrueCrypt SHA512 + XTS 1024 bit (legacy)",
            "6223 - TrueCrypt SHA512 + XTS 1536 bit (legacy)",
            "29321 - TrueCrypt SHA512 + XTS 512 bit",
            "29322 - TrueCrypt SHA512 + XTS 1024 bit",
            "29323 - TrueCrypt SHA512 + XTS 1536 bit",
            "6231 - TrueCrypt Whirlpool + XTS 512 bit (legacy)",
            "6232 - TrueCrypt Whirlpool + XTS 1024 bit (legacy)",
            "6233 - TrueCrypt Whirlpool + XTS 1536 bit (legacy)",
            "29331 - TrueCrypt Whirlpool + XTS 512 bit",
            "29332 - TrueCrypt Whirlpool + XTS 1024 bit",
            "29333 - TrueCrypt Whirlpool + XTS 1536 bit",
            "12200 - eCryptfs",
            
            # Document
            "10400 - PDF 1.1 - 1.3 (Acrobat 2 - 4)",
            "10410 - PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1",
            "10420 - PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2",
            "10500 - PDF 1.4 - 1.6 (Acrobat 5 - 8)",
            "25400 - PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass",
            "10600 - PDF 1.7 Level 3 (Acrobat 9)",
            "10700 - PDF 1.7 Level 8 (Acrobat 10 - 11)",
            "9400 - MS Office 2007",
            "9500 - MS Office 2010",
            "9600 - MS Office 2013",
            "25300 - MS Office 2016 - SheetProtection",
            "9700 - MS Office <= 2003 $0/$1, MD5 + RC4",
            "9710 - MS Office <= 2003 $0/$1, MD5 + RC4, collider #1",
            "9720 - MS Office <= 2003 $0/$1, MD5 + RC4, collider #2",
            "9810 - MS Office <= 2003 $3, SHA1 + RC4, collider #1",
            "9820 - MS Office <= 2003 $3, SHA1 + RC4, collider #2",
            "9800 - MS Office <= 2003 $3/$4, SHA1 + RC4",
            "18400 - Open Document Format (ODF) 1.2 (SHA-256, AES)",
            "18600 - Open Document Format (ODF) 1.1 (SHA-1, Blowfish)",
            "16200 - Apple Secure Notes",
            "23300 - Apple iWork",
            
            # Password Manager
            "6600 - 1Password, agilekeychain",
            "8200 - 1Password, cloudkeychain",
            "9000 - Password Safe v2",
            "5200 - Password Safe v3",
            "6800 - LastPass + LastPass sniffed",
            "13400 - KeePass 1 (AES/Twofish) and KeePass 2 (AES)",
            "29700 - KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode",
            "23400 - Bitwarden",
            "16900 - Ansible Vault",
            "26000 - Mozilla key3.db",
            "26100 - Mozilla key4.db",
            "23100 - Apple Keychain",
            
            # Archive
            "11600 - 7-Zip",
            "12500 - RAR3-hp",
            "23800 - RAR3-p (Compressed)",
            "23700 - RAR3-p (Uncompressed)",
            "13000 - RAR5",
            "17220 - PKZIP (Compressed Multi-File)",
            "17200 - PKZIP (Compressed)",
            "17225 - PKZIP (Mixed Multi-File)",
            "17230 - PKZIP (Mixed Multi-File Checksum-Only)",
            "17210 - PKZIP (Uncompressed)",
            "20500 - PKZIP Master Key",
            "20510 - PKZIP Master Key (6 byte optimization)",
            "23001 - SecureZIP AES-128",
            "23002 - SecureZIP AES-192",
            "23003 - SecureZIP AES-256",
            "13600 - WinZip",
            "18900 - Android Backup",
            "24700 - Stuffit5",
            "13200 - AxCrypt 1",
            "13300 - AxCrypt 1 in-memory SHA1",
            "23500 - AxCrypt 2 AES-128",
            "23600 - AxCrypt 2 AES-256",
            "14700 - iTunes backup < 10.0",
            "14800 - iTunes backup >= 10.0",
            
            # Forums, CMS, E-Commerce
            "8400 - WBB3 (Woltlab Burning Board)",
            "2612 - PHPS",
            "121 - SMF (Simple Machines Forum) > v1.1",
            "3711 - MediaWiki B type",
            "4521 - Redmine",
            "24800 - Umbraco HMAC-SHA1",
            "11 - Joomla < 2.5.18",
            "13900 - OpenCart",
            "11000 - PrestaShop",
            "16000 - Tripcode",
            "7900 - Drupal7",
            "4522 - PunBB",
            "2811 - MyBB 1.2+, IPB2+ (Invision Power Board)",
            "2611 - vBulletin < v3.8.5",
            "2711 - vBulletin >= v3.8.5",
            "25600 - bcrypt(md5($pass)) / bcryptmd5",
            "25800 - bcrypt(sha1($pass)) / bcryptsha1",
            "28400 - bcrypt(sha512($pass)) / bcryptsha512",
            "21 - osCommerce, xt:Commerce",
            
            # One-Time Password
            "18100 - TOTP (HMAC-SHA1)",
            
            # Plaintext
            "2000 - STDOUT",
            "99999 - Plaintext",
            
            # Framework
            "21600 - Web2py pbkdf2-sha512",
            "10000 - Django (PBKDF2-SHA256)",
            "124 - Django (SHA-1)",
            "12001 - Atlassian (PBKDF2-HMAC-SHA1)",
            "19500 - Ruby on Rails Restful-Authentication",
            "27200 - Ruby on Rails Restful Auth (one round, no sitekey)",
            "30000 - Python Werkzeug MD5 (HMAC-MD5 (key = $salt))",
            "30120 - Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))",
            "20200 - Python passlib pbkdf2-sha512",
            "20300 - Python passlib pbkdf2-sha256",
            "20400 - Python passlib pbkdf2-sha1",
            
            # Private Key
            "24410 - PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)",
            "24420 - PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)",
            "15500 - JKS Java Key Store Private Keys (SHA1)",
            "22911 - RSA/DSA/EC/OpenSSH Private Keys ($0$)",
            "22921 - RSA/DSA/EC/OpenSSH Private Keys ($6$)",
            "22931 - RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)",
            "22941 - RSA/DSA/EC/OpenSSH Private Keys ($4$)",
            "22951 - RSA/DSA/EC/OpenSSH Private Keys ($5$)",
            
            # Instant Messaging Service
            "23200 - XMPP SCRAM PBKDF2-SHA1",
            "28300 - Teamspeak 3 (channel hash)",
            "22600 - Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)",
            "24500 - Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)",
            "22301 - Telegram Mobile App Passcode (SHA256)",
            "23 - Skype",
            
            # Cryptocurrency Wallet
            "29600 - Terra Station Wallet (AES256-CBC(PBKDF2($pass)))",
            "26600 - MetaMask Wallet",
            "21000 - BitShares v0.x - sha512(sha512_bin(pass))",
            "28501 - Bitcoin WIF private key (P2PKH), compressed",
            "28502 - Bitcoin WIF private key (P2PKH), uncompressed",
            "28503 - Bitcoin WIF private key (P2WPKH, Bech32), compressed",
            "28504 - Bitcoin WIF private key (P2WPKH, Bech32), uncompressed",
            "28505 - Bitcoin WIF private key (P2SH(P2WPKH)), compressed",
            "28506 - Bitcoin WIF private key (P2SH(P2WPKH)), uncompressed",
            "11300 - Bitcoin/Litecoin wallet.dat",
            "16600 - Electrum Wallet (Salt-Type 1-3)",
            "21700 - Electrum Wallet (Salt-Type 4)",
            "21800 - Electrum Wallet (Salt-Type 5)",
            "12700 - Blockchain, My Wallet",
            "15200 - Blockchain, My Wallet, V2",
            "18800 - Blockchain, My Wallet, Second Password (SHA256)",
            "25500 - Stargazer Stellar Wallet XLM",
            "16300 - Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
            "15600 - Ethereum Wallet, PBKDF2-HMAC-SHA256",
            "15700 - Ethereum Wallet, SCRYPT",
            "22500 - MultiBit Classic .key (MD5)",
            "27700 - MultiBit Classic .wallet (scrypt)",
            "22700 - MultiBit HD (scrypt)",
            "28200 - Exodus Desktop Wallet (scrypt)"
        ])
        
        # 保存所有哈希类型项目用于搜索过滤
        self.all_hash_types = [self.hash_type_combo.itemText(i) for i in range(self.hash_type_combo.count())]
        
        # 连接搜索框的文本变化信号
        self.hash_type_search.textChanged.connect(self.filter_hash_types)
        
        self.setup_input_layout()
        left_layout.addWidget(self.input_group)
        
        # 攻击模式 - 改成一行
        attack_layout = QHBoxLayout()
        attack_layout.addWidget(QLabel("攻击模式:"))
        self.attack_mode_combo = QComboBox()
        self.attack_mode_combo.addItems([
            "0 - 字典攻击",
            "1 - 组合攻击",
            "3 - 掩码攻击",
            "6 - 混合字典+掩码",
            "7 - 混合掩码+字典",
            "9 - 关联攻击"
        ])
        # 默认选中掩码攻击
        self.attack_mode_combo.setCurrentText("3 - 掩码攻击")
        attack_layout.addWidget(self.attack_mode_combo)
        attack_layout.addStretch()
        
        left_layout.addLayout(attack_layout)
        
        # 字典和掩码设置
        dict_group = QGroupBox("字典和掩码")
        dict_layout = QGridLayout(dict_group)
        
        # 字典文件行
        self.dict_label = QLabel("字典文件:")
        dict_layout.addWidget(self.dict_label, 0, 0)
        self.dict_path_edit = QLineEdit()
        dict_layout.addWidget(self.dict_path_edit, 0, 1)
        self.browse_dict_btn = QPushButton("浏览")
        self.browse_dict_btn.setFixedWidth(60)
        self.browse_dict_btn.clicked.connect(self.browse_dict)
        dict_layout.addWidget(self.browse_dict_btn, 0, 2)
        
        # 设置字典布局的列拉伸比例
        dict_layout.setColumnStretch(0, 0)  # 标签列不拉伸
        dict_layout.setColumnStretch(1, 1)  # 输入框列拉伸
        dict_layout.setColumnStretch(2, 0)  # 按钮列不拉伸
        
        # 掩码行
        self.mask_label = QLabel("掩码:")
        dict_layout.addWidget(self.mask_label, 1, 0)
        self.mask_edit = QLineEdit("?a?a?a?a?a?a?a?a")
        self.mask_edit.textChanged.connect(self.update_command_preview)
        self.mask_edit.textChanged.connect(self.save_config)  # 自动保存配置
        self.mask_edit.textChanged.connect(self.calculate_main_candidates)  # 计算候选数量
        dict_layout.addWidget(self.mask_edit, 1, 1)
        
        # 掩码生成器按钮
        self.mask_generator_btn = QPushButton("掩码生成器")
        self.mask_generator_btn.clicked.connect(self.open_mask_generator)
        dict_layout.addWidget(self.mask_generator_btn, 1, 2)
        
        # 常用掩码模板
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("常用模板:"))
        self.mask_template_combo = QComboBox()
        self.mask_template_combo.addItems([
            "自定义",
            "?d?d?d?d?d?d (6位数字)",
            "?d?d?d?d?d?d?d?d (8位数字)",
            "?l?l?l?l?l?l (6位小写字母)",
            "?u?l?l?l?l?l (首字母大写+5位小写)",
            "?l?l?l?l?d?d (4位字母+2位数字)",
            "?l?l?l?l?l?l?d?d (6位字母+2位数字)",
            "?u?l?l?l?l?l?d?d (首字母大写+5位字母+2位数字)",
            "?a?a?a?a?a?a (6位任意字符)",
            "?a?a?a?a?a?a?a?a (8位任意字符)"
        ])
        self.mask_template_combo.currentTextChanged.connect(self.on_mask_template_changed)
        template_layout.addWidget(self.mask_template_combo)
        template_layout.addStretch()
        dict_layout.addLayout(template_layout, 2, 0, 1, 3)
        
        # 掩码说明 - 字号调大
        self.mask_info = QLabel("?l=小写 ?u=大写 ?d=数字 ?s=符号 ?a=全部")
        self.mask_info.setStyleSheet("color: gray; font-size: 12px;")
        dict_layout.addWidget(self.mask_info, 3, 1, 1, 2)
        
        # 预计候选数量显示
        self.main_candidates_label = QLabel("预计候选数量: 计算中...")
        self.main_candidates_label.setStyleSheet("color: blue; font-weight: bold; font-size: 12px;")
        dict_layout.addWidget(self.main_candidates_label, 4, 1, 1, 2)
        
        # 自定义字符集 (-1 -2 -3 -4)
        charset_label = QLabel("自定义字符集:")
        dict_layout.addWidget(charset_label, 5, 0)
        
        # -1 字符集
        dict_layout.addWidget(QLabel("-1:"), 6, 0)
        self.charset1_edit = QLineEdit()
        self.charset1_edit.setPlaceholderText("例如: abcdef0123456789")
        self.charset1_edit.textChanged.connect(self.update_command_preview)
        self.charset1_edit.textChanged.connect(self.save_config)  # 自动保存配置
        self.charset1_edit.textChanged.connect(self.calculate_main_candidates)  # 计算候选数量
        dict_layout.addWidget(self.charset1_edit, 6, 1, 1, 2)
        
        # -2 字符集
        dict_layout.addWidget(QLabel("-2:"), 7, 0)
        self.charset2_edit = QLineEdit()
        self.charset2_edit.setPlaceholderText("例如: ABCDEF")
        self.charset2_edit.textChanged.connect(self.update_command_preview)
        self.charset2_edit.textChanged.connect(self.save_config)  # 自动保存配置
        self.charset2_edit.textChanged.connect(self.calculate_main_candidates)  # 计算候选数量
        dict_layout.addWidget(self.charset2_edit, 7, 1, 1, 2)
        
        # -3 字符集
        dict_layout.addWidget(QLabel("-3:"), 8, 0)
        self.charset3_edit = QLineEdit()
        self.charset3_edit.setPlaceholderText("例如: !@#$%^&*")
        self.charset3_edit.textChanged.connect(self.update_command_preview)
        self.charset3_edit.textChanged.connect(self.save_config)  # 自动保存配置
        self.charset3_edit.textChanged.connect(self.calculate_main_candidates)  # 计算候选数量
        dict_layout.addWidget(self.charset3_edit, 8, 1, 1, 2)
        
        # -4 字符集
        dict_layout.addWidget(QLabel("-4:"), 9, 0)
        self.charset4_edit = QLineEdit()
        self.charset4_edit.setPlaceholderText("例如: 0123456789")
        self.charset4_edit.textChanged.connect(self.update_command_preview)
        self.charset4_edit.textChanged.connect(self.save_config)  # 自动保存配置
        self.charset4_edit.textChanged.connect(self.calculate_main_candidates)  # 计算候选数量
        dict_layout.addWidget(self.charset4_edit, 9, 1, 1, 2)
        
        # 自定义字符集说明
        charset_info = QLabel("在掩码中使用 ?1 ?2 ?3 ?4 来引用自定义字符集")
        charset_info.setStyleSheet("color: gray; font-size: 12px;")
        dict_layout.addWidget(charset_info, 10, 1, 1, 2)
        
        left_layout.addWidget(dict_group)
        
        # 其他选项 - 改成一行
        other_group = QGroupBox("其他选项")
        options_layout = QHBoxLayout(other_group)
        
        self.show_potfile_check = QCheckBox("显示已破解的密码")
        self.quiet_check = QCheckBox("安静模式")
        self.force_check = QCheckBox("忽略警告")
        
        options_layout.addWidget(self.show_potfile_check)
        options_layout.addWidget(self.quiet_check)
        options_layout.addWidget(self.force_check)
        options_layout.addStretch()
        
        left_layout.addWidget(other_group)
        
        # 增量设置
        increment_group = QGroupBox("增量设置")
        increment_layout = QGridLayout(increment_group)
        
        self.increment_check = QCheckBox("启用增量")
        increment_layout.addWidget(self.increment_check, 0, 0)
        
        increment_layout.addWidget(QLabel("最小长度:"), 0, 1)
        self.min_len_edit = QLineEdit("1")
        self.min_len_edit.setMaximumWidth(50)
        increment_layout.addWidget(self.min_len_edit, 0, 2)
        
        increment_layout.addWidget(QLabel("最大长度:"), 0, 3)
        self.max_len_edit = QLineEdit("8")
        self.max_len_edit.setMaximumWidth(50)
        increment_layout.addWidget(self.max_len_edit, 0, 4)
        
        left_layout.addWidget(increment_group)
        
        # 控制按钮
        button_layout = QVBoxLayout()
        
        # 主要控制按钮
        main_button_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始爆破")
        self.start_btn.clicked.connect(self.start_crack)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_crack)
        self.stop_btn.setEnabled(False)
        
        main_button_layout.addWidget(self.start_btn)
        main_button_layout.addWidget(self.stop_btn)
        button_layout.addLayout(main_button_layout)
        
        # Hashcat控制功能已移除
        left_layout.addLayout(button_layout)
        
        splitter.addWidget(left_panel)
        
        # 右侧面板
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # 命令预览 - 变矮
        cmd_group = QGroupBox("命令预览")
        cmd_layout = QVBoxLayout(cmd_group)
        cmd_layout.setContentsMargins(5, 5, 5, 5)  # 减小内边距
        cmd_layout.setSpacing(2)  # 减小间距
        self.cmd_text = QTextEdit()
        self.cmd_text.setFixedHeight(65)  # 进一步减小高度
        self.cmd_text.setReadOnly(True)
        cmd_layout.addWidget(self.cmd_text)
        cmd_group.setMaximumHeight(100)  # 限制整个组的最大高度
        right_layout.addWidget(cmd_group)
        
        # 创建标签页容器
        self.right_tab_widget = QTabWidget()
        
        # 执行日志标签页
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        self.log_text = QTextEdit()
        self.log_text.setMinimumHeight(300)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        log_layout.addWidget(self.progress_bar)
        
        self.right_tab_widget.addTab(log_widget, "执行日志")
        
        right_layout.addWidget(self.right_tab_widget)
        
        splitter.addWidget(right_panel)
        
        # 设置分割器比例
        splitter.setSizes([400, 600])
        
        # 初始化界面状态
        self.on_decrypt_type_changed()
        self.on_attack_mode_changed()
    
    def filter_hash_types(self):
        """根据搜索框内容过滤哈希类型"""
        function_logger.debug("HashcatGUI.filter_hash_types called")
        search_text = self.hash_type_search.text().lower()
        
        # 清空当前项目
        self.hash_type_combo.clear()
        
        # 如果搜索框为空，显示所有项目
        if not search_text:
            self.hash_type_combo.addItems(self.all_hash_types)
        else:
            # 过滤匹配的项目
            filtered_items = [item for item in self.all_hash_types 
                            if search_text in item.lower()]
            self.hash_type_combo.addItems(filtered_items)
    
    def setup_input_layout(self):
        """设置输入布局"""
        function_logger.debug("HashcatGUI.setup_input_layout called")
        self.input_layout.addWidget(self.file_label, 0, 0)
        self.input_layout.addWidget(self.file_path_edit, 0, 1)
        self.input_layout.addWidget(self.browse_file_btn, 0, 2)
        
        self.input_layout.addWidget(self.hash_label, 1, 0)
        self.input_layout.addWidget(self.hash_edit, 1, 1, 1, 2)
        
        self.input_layout.addWidget(self.batch_label, 2, 0)
        self.input_layout.addWidget(self.batch_path_edit, 2, 1)
        self.input_layout.addWidget(self.browse_batch_btn, 2, 2)
        
        self.input_layout.addWidget(self.hash_type_label, 3, 0)
        self.input_layout.addWidget(self.hash_type_search, 3, 1)
        self.input_layout.addWidget(self.hash_type_combo, 4, 1)
        
        # 设置列拉伸比例，让输入框占据更多空间
        self.input_layout.setColumnStretch(0, 0)  # 标签列不拉伸
        self.input_layout.setColumnStretch(1, 1)  # 输入框列拉伸
        self.input_layout.setColumnStretch(2, 0)  # 按钮列不拉伸
    
    def create_config_tab(self):
        """创建配置标签页"""
        function_logger.debug("HashcatGUI.create_config_tab called")
        config_widget = QWidget()
        self.tab_widget.addTab(config_widget, "配置")
        
        layout = QVBoxLayout(config_widget)
        
        # 路径配置
        path_group = QGroupBox("路径配置")
        path_layout = QGridLayout(path_group)
        
        path_layout.addWidget(QLabel("John the Ripper路径:"), 0, 0)
        self.john_path_edit = QLineEdit(self.john_path)
        path_layout.addWidget(self.john_path_edit, 0, 1)
        self.browse_john_btn = QPushButton("浏览")
        self.browse_john_btn.clicked.connect(self.browse_john_path)
        path_layout.addWidget(self.browse_john_btn, 0, 2)
        
        path_layout.addWidget(QLabel("Hashcat路径:"), 1, 0)
        self.hashcat_path_edit = QLineEdit(self.hashcat_path)
        path_layout.addWidget(self.hashcat_path_edit, 1, 1)
        self.browse_hashcat_btn = QPushButton("浏览")
        self.browse_hashcat_btn.clicked.connect(self.browse_hashcat_path)
        path_layout.addWidget(self.browse_hashcat_btn, 1, 2)
        
        self.save_config_btn = QPushButton("保存配置")
        self.save_config_btn.clicked.connect(self.save_config)
        path_layout.addWidget(self.save_config_btn, 2, 1)
        
        self.config_status_label = QLabel("")
        path_layout.addWidget(self.config_status_label, 3, 1)
        
        layout.addWidget(path_group)
        
        # 性能设置
        perf_group = QGroupBox("性能设置")
        perf_layout = QGridLayout(perf_group)
        
        perf_layout.addWidget(QLabel("工作负载:"), 0, 0)
        self.workload_combo = QComboBox()
        self.workload_combo.addItems(["1 - 低", "2 - 默认", "3 - 高", "4 - 疯狂"])
        self.workload_combo.setCurrentText("3 - 高")
        perf_layout.addWidget(self.workload_combo, 0, 1)
        
        # 内核加速设置
        perf_layout.addWidget(QLabel("内核循环数(-n):"), 1, 0)
        self.kernel_loops_edit = QLineEdit()
        self.kernel_loops_edit.setPlaceholderText("留空使用默认值")
        perf_layout.addWidget(self.kernel_loops_edit, 1, 1)
        
        perf_layout.addWidget(QLabel("内核线程数(-u):"), 2, 0)
        self.kernel_threads_edit = QLineEdit()
        self.kernel_threads_edit.setPlaceholderText("留空使用默认值")
        perf_layout.addWidget(self.kernel_threads_edit, 2, 1)
        
        # 优化选项
        self.optimized_kernel_check = QCheckBox("启用优化内核(-O)")
        self.optimized_kernel_check.setToolTip("启用优化内核可能提高性能，但会限制密码长度")
        perf_layout.addWidget(self.optimized_kernel_check, 3, 0, 1, 2)
        
        layout.addWidget(perf_group)
        
        # 安全选项
        security_group = QGroupBox("安全选项")
        security_layout = QGridLayout(security_group)
        
        security_layout.addWidget(QLabel("温度限制(°C):"), 0, 0)
        self.temp_abort_edit = QLineEdit()
        self.temp_abort_edit.setPlaceholderText("例如: 90")
        self.temp_abort_edit.setToolTip("当GPU温度超过此值时自动停止")
        security_layout.addWidget(self.temp_abort_edit, 0, 1)
        
        security_layout.addWidget(QLabel("运行时间限制(秒):"), 1, 0)
        self.runtime_edit = QLineEdit()
        self.runtime_edit.setPlaceholderText("例如: 3600 (1小时)")
        self.runtime_edit.setToolTip("运行指定时间后自动停止")
        security_layout.addWidget(self.runtime_edit, 1, 1)
        
        security_layout.addWidget(QLabel("状态更新间隔(秒):"), 2, 0)
        self.status_timer_edit = QLineEdit("5")
        self.status_timer_edit.setToolTip("状态信息更新间隔，默认5秒")
        security_layout.addWidget(self.status_timer_edit, 2, 1)
        
        layout.addWidget(security_group)
        
        # 设备选择
        device_group = QGroupBox("设备选择")
        device_layout = QVBoxLayout(device_group)
        
        # 设备选择说明
        device_info = QLabel("选择要使用的计算设备（对应-d参数）。默认全选表示使用所有可用设备。")
        device_info.setWordWrap(True)
        device_layout.addWidget(device_info)
        
        # 设备列表和控制按钮
        device_control_layout = QHBoxLayout()
        
        # 刷新设备列表按钮
        self.refresh_devices_btn = QPushButton("刷新设备列表")
        device_control_layout.addWidget(self.refresh_devices_btn)
        
        # 全选/全不选按钮
        self.select_all_devices_btn = QPushButton("全选")
        device_control_layout.addWidget(self.select_all_devices_btn)
        
        self.deselect_all_devices_btn = QPushButton("全不选")
        device_control_layout.addWidget(self.deselect_all_devices_btn)
        
        device_control_layout.addStretch()
        device_layout.addLayout(device_control_layout)
        
        # 设备列表显示区域
        self.device_list_widget = QWidget()
        self.device_list_layout = QVBoxLayout(self.device_list_widget)
        device_layout.addWidget(self.device_list_widget)
        
        # 设备复选框列表（动态生成）
        self.device_checkboxes = []
        
        # 手动输入设备ID（高级选项）
        manual_device_layout = QHBoxLayout()
        manual_device_layout.addWidget(QLabel("手动指定设备ID:"))
        self.manual_device_edit = QLineEdit()
        self.manual_device_edit.setPlaceholderText("例如: 1,2,3 或留空使用上方选择的设备")
        manual_device_layout.addWidget(self.manual_device_edit)
        device_layout.addLayout(manual_device_layout)
        
        layout.addWidget(device_group)
        
        # 输出设置
        output_group = QGroupBox("输出设置")
        output_layout = QGridLayout(output_group)
        
        output_layout.addWidget(QLabel("输出文件:"), 0, 0)
        self.output_file_edit = QLineEdit()
        output_layout.addWidget(self.output_file_edit, 0, 1)
        self.browse_output_btn = QPushButton("浏览")
        self.browse_output_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(self.browse_output_btn, 0, 2)
        
        output_layout.addWidget(QLabel("输出格式:"), 1, 0)
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems([
            "1 - hash", "2 - plain", "3 - hash:plain", 
            "4 - hex_plain", "5 - hash:hex_plain"
        ])
        self.output_format_combo.setCurrentText("3 - hash:plain")
        output_layout.addWidget(self.output_format_combo, 1, 1)
        
        layout.addWidget(output_group)
        
        layout.addStretch()
    
    def create_dict_generator_tab(self):
        """创建字典生成器标签页"""
        function_logger.debug("HashcatGUI.create_dict_generator_tab called")
        dict_gen_widget = QWidget()
        self.tab_widget.addTab(dict_gen_widget, "字典生成器")
        
        layout = QVBoxLayout(dict_gen_widget)
        
        # 创建滚动区域
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # 基础字典生成
        basic_container = QWidget()
        basic_container_layout = QVBoxLayout(basic_container)
        basic_container_layout.setContentsMargins(5, 5, 5, 5)
        basic_container_layout.setSpacing(5)
        
        # 标题行：标题 + 启用复选框
        basic_header_layout = QHBoxLayout()
        basic_header_layout.setContentsMargins(0, 0, 0, 0)
        basic_header_layout.setSpacing(10)
        basic_title_label = QLabel("基础字典生成")
        basic_title_label.setStyleSheet("font-weight: bold; font-size: 12px; margin: 0px; padding: 2px;")
        self.basic_enable_check = QCheckBox("启用")
        self.basic_enable_check.setChecked(True)
        self.basic_enable_check.stateChanged.connect(self.toggle_basic_controls)
        self.basic_enable_check.setStyleSheet("margin: 0px; padding: 2px;")
        basic_header_layout.addWidget(basic_title_label)
        basic_header_layout.addWidget(self.basic_enable_check)
        basic_header_layout.addStretch()
        basic_container_layout.addLayout(basic_header_layout)
        
        # 内容区域
        basic_group = QGroupBox()
        basic_group.setStyleSheet("QGroupBox { border: 1px solid gray; margin: 2px; padding: 3px; }")
        
        basic_layout = QGridLayout(basic_group)
        
        # 长度设置和字符集选择（合并到一行）
        basic_layout.addWidget(QLabel("密码设置:"), 1, 0)
        length_charset_layout = QHBoxLayout()
        
        # 长度设置部分
        length_charset_layout.addWidget(QLabel("长度:"))
        length_charset_layout.addWidget(QLabel("最小:"))
        self.min_length_spin = QSpinBox()
        self.min_length_spin.setRange(1, 20)
        self.min_length_spin.setValue(4)
        length_charset_layout.addWidget(self.min_length_spin)
        
        length_charset_layout.addWidget(QLabel("最大:"))
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 20)
        self.max_length_spin.setValue(8)
        length_charset_layout.addWidget(self.max_length_spin)
        
        # 分隔符
        length_charset_layout.addWidget(QLabel("|"))
        
        # 字符集选择部分
        length_charset_layout.addWidget(QLabel("字符集:"))
        self.charset_checks = {}
        
        self.charset_checks['lowercase'] = QCheckBox("小写")
        self.charset_checks['lowercase'].setChecked(True)
        length_charset_layout.addWidget(self.charset_checks['lowercase'])
        
        self.charset_checks['uppercase'] = QCheckBox("大写")
        length_charset_layout.addWidget(self.charset_checks['uppercase'])
        
        self.charset_checks['digits'] = QCheckBox("数字")
        self.charset_checks['digits'].setChecked(True)
        length_charset_layout.addWidget(self.charset_checks['digits'])
        
        self.charset_checks['symbols'] = QCheckBox("符号")
        length_charset_layout.addWidget(self.charset_checks['symbols'])
        
        length_charset_layout.addStretch()
        basic_layout.addLayout(length_charset_layout, 1, 1, 1, 2)
        
        # 自定义字符集
        basic_layout.addWidget(QLabel("自定义字符:"), 2, 0)
        self.custom_charset_edit = QLineEdit()
        self.custom_charset_edit.setPlaceholderText("例如: 中文字符、特殊符号等")
        basic_layout.addWidget(self.custom_charset_edit, 2, 1, 1, 2)
        
        basic_container_layout.addWidget(basic_group)
        scroll_layout.addWidget(basic_container)
        
        # 社工字典生成
        social_container = QWidget()
        social_container_layout = QVBoxLayout(social_container)
        social_container_layout.setContentsMargins(5, 5, 5, 5)
        social_container_layout.setSpacing(5)
        
        # 标题行：标题 + 启用复选框
        social_header_layout = QHBoxLayout()
        social_header_layout.setContentsMargins(0, 0, 0, 0)
        social_header_layout.setSpacing(10)
        social_title_label = QLabel("社工字典生成")
        social_title_label.setStyleSheet("font-weight: bold; font-size: 12px; margin: 0px; padding: 2px;")
        self.social_enable_check = QCheckBox("启用")
        self.social_enable_check.setChecked(True)
        self.social_enable_check.stateChanged.connect(self.toggle_social_controls)
        self.social_enable_check.setStyleSheet("margin: 0px; padding: 2px;")
        social_header_layout.addWidget(social_title_label)
        social_header_layout.addWidget(self.social_enable_check)
        social_header_layout.addStretch()
        social_container_layout.addLayout(social_header_layout)
        
        # 内容区域
        social_group = QGroupBox()
        social_group.setStyleSheet("QGroupBox { border: 1px solid gray; margin: 2px; padding: 3px; }")
        
        social_layout = QGridLayout(social_group)
        
        # 个人信息
        social_layout.addWidget(QLabel("姓名:"), 0, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如: 张三、zhangsan")
        social_layout.addWidget(self.name_edit, 0, 1)
        
        social_layout.addWidget(QLabel("生日:"), 0, 2)
        self.birthday_edit = QLineEdit()
        self.birthday_edit.setPlaceholderText("例如: 19900101、0101")
        social_layout.addWidget(self.birthday_edit, 0, 3)
        
        social_layout.addWidget(QLabel("电话:"), 1, 0)
        self.phone_edit = QLineEdit()
        self.phone_edit.setPlaceholderText("例如: 13812345678")
        social_layout.addWidget(self.phone_edit, 1, 1)
        
        social_layout.addWidget(QLabel("QQ/微信:"), 1, 2)
        self.qq_edit = QLineEdit()
        self.qq_edit.setPlaceholderText("例如: 123456789")
        social_layout.addWidget(self.qq_edit, 1, 3)
        
        social_layout.addWidget(QLabel("公司/学校:"), 2, 0)
        self.company_edit = QLineEdit()
        self.company_edit.setPlaceholderText("例如: 阿里巴巴、清华大学")
        social_layout.addWidget(self.company_edit, 2, 1)
        
        social_layout.addWidget(QLabel("爱好/宠物:"), 2, 2)
        self.hobby_edit = QLineEdit()
        self.hobby_edit.setPlaceholderText("例如: 篮球、小狗")
        social_layout.addWidget(self.hobby_edit, 2, 3)
        
        # 年份范围和常用后缀（合并到一行）
        social_layout.addWidget(QLabel("后缀设置:"), 3, 0)
        year_suffix_layout = QHBoxLayout()
        
        # 年份范围部分
        self.year_checkbox = QCheckBox("年份:")
        year_suffix_layout.addWidget(self.year_checkbox)
        year_suffix_layout.addWidget(QLabel("从:"))
        self.start_year_spin = QSpinBox()
        self.start_year_spin.setRange(1950, 2030)
        self.start_year_spin.setValue(1980)
        self.start_year_spin.setEnabled(False)  # 默认禁用
        year_suffix_layout.addWidget(self.start_year_spin)
        
        year_suffix_layout.addWidget(QLabel("到:"))
        self.end_year_spin = QSpinBox()
        self.end_year_spin.setRange(1950, 2030)
        self.end_year_spin.setValue(2024)
        self.end_year_spin.setEnabled(False)  # 默认禁用
        year_suffix_layout.addWidget(self.end_year_spin)
        
        # 分隔符
        year_suffix_layout.addWidget(QLabel("|"))
        
        # 常用后缀部分
        year_suffix_layout.addWidget(QLabel("常用后缀:"))
        self.suffix_checks = {}
        suffixes = ['123', '666', '888', '!', '@', '#', '520', '1314', '2024']
        for suffix in suffixes:
            self.suffix_checks[suffix] = QCheckBox(suffix)
            year_suffix_layout.addWidget(self.suffix_checks[suffix])
        
        year_suffix_layout.addStretch()
        social_layout.addLayout(year_suffix_layout, 3, 1, 1, 3)
        
        social_container_layout.addWidget(social_group)
        scroll_layout.addWidget(social_container)
        
        # 手动添加字典条目
        manual_container = QWidget()
        manual_container_layout = QVBoxLayout(manual_container)
        manual_container_layout.setContentsMargins(5, 5, 5, 5)
        manual_container_layout.setSpacing(5)
        
        # 标题行：标题 + 启用复选框
        manual_header_layout = QHBoxLayout()
        manual_header_layout.setContentsMargins(0, 0, 0, 0)
        manual_header_layout.setSpacing(10)
        manual_title_label = QLabel("手动添加字典条目")
        manual_title_label.setStyleSheet("font-weight: bold; font-size: 12px; margin: 0px; padding: 2px;")
        self.manual_enable_check = QCheckBox("启用")
        self.manual_enable_check.setChecked(True)
        self.manual_enable_check.stateChanged.connect(self.toggle_manual_controls)
        self.manual_enable_check.setStyleSheet("margin: 0px; padding: 2px;")
        manual_header_layout.addWidget(manual_title_label)
        manual_header_layout.addWidget(self.manual_enable_check)
        manual_header_layout.addStretch()
        manual_container_layout.addLayout(manual_header_layout)
        
        # 内容区域
        manual_group = QGroupBox()
        manual_group.setStyleSheet("QGroupBox { border: 1px solid gray; margin: 2px; padding: 3px; }")
        
        manual_layout = QGridLayout(manual_group)
        
        # 输入框和添加按钮
        manual_layout.addWidget(QLabel("添加密码:"), 0, 0)
        self.manual_password_edit = QLineEdit()
        self.manual_password_edit.setPlaceholderText("输入要添加的密码...")
        self.manual_password_edit.returnPressed.connect(self.add_manual_password)
        manual_layout.addWidget(self.manual_password_edit, 0, 1)
        
        self.add_password_btn = QPushButton("添加")
        self.add_password_btn.clicked.connect(self.add_manual_password)
        manual_layout.addWidget(self.add_password_btn, 0, 2)
        
        # 已添加的密码列表
        manual_layout.addWidget(QLabel("已添加的密码:"), 1, 0)
        self.manual_passwords_list = QTextEdit()
        self.manual_passwords_list.setMaximumHeight(150)
        self.manual_passwords_list.setPlaceholderText("手动添加的密码将显示在这里...")
        self.manual_passwords_list.setReadOnly(True)
        manual_layout.addWidget(self.manual_passwords_list, 1, 1, 1, 2)
        
        # 操作按钮
        manual_btn_layout = QHBoxLayout()
        self.clear_manual_btn = QPushButton("清空列表")
        self.clear_manual_btn.clicked.connect(self.clear_manual_passwords)
        manual_btn_layout.addWidget(self.clear_manual_btn)
        
        self.import_manual_btn = QPushButton("从文件导入")
        self.import_manual_btn.clicked.connect(self.import_manual_passwords)
        manual_btn_layout.addWidget(self.import_manual_btn)
        
        manual_btn_layout.addStretch()
        manual_layout.addLayout(manual_btn_layout, 2, 1, 1, 2)
        
        # 手动密码计数标签
        self.manual_count_label = QLabel("手动添加: 0 条")
        self.manual_count_label.setStyleSheet("color: green; font-weight: bold;")
        manual_layout.addWidget(self.manual_count_label, 2, 0)
        
        manual_container_layout.addWidget(manual_group)
        scroll_layout.addWidget(manual_container)
        
        # 预览和生成控制
        control_group = QGroupBox("预览和生成")
        control_layout = QGridLayout(control_group)
        
        # 预览按钮和信息
        preview_layout = QHBoxLayout()
        self.preview_btn = QPushButton("预览字典")
        self.preview_btn.clicked.connect(self.preview_dictionary)
        preview_layout.addWidget(self.preview_btn)
        
        self.dict_info_label = QLabel("预计条数: 0 | 预计大小: 0 KB")
        self.dict_info_label.setStyleSheet("color: blue; font-weight: bold;")
        preview_layout.addWidget(self.dict_info_label)
        
        preview_layout.addStretch()
        control_layout.addLayout(preview_layout, 0, 0, 1, 2)
        
        # 预览文本框
        self.preview_text = QTextEdit()
        self.preview_text.setMaximumHeight(200)
        self.preview_text.setPlaceholderText("点击'预览字典'查看生成的密码样例...")
        control_layout.addWidget(self.preview_text, 1, 0, 1, 2)
        
        # 文件名和生成按钮
        control_layout.addWidget(QLabel("文件名:"), 2, 0)
        filename_layout = QHBoxLayout()
        
        self.filename_edit = QLineEdit("custom_dict.txt")
        filename_layout.addWidget(self.filename_edit)
        
        self.generate_btn = QPushButton("生成字典")
        self.generate_btn.clicked.connect(self.generate_dictionary)
        self.generate_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")
        filename_layout.addWidget(self.generate_btn)
        
        control_layout.addLayout(filename_layout, 2, 1)
        
        scroll_layout.addWidget(control_group)
        
        # 初始化手动密码列表
        self.manual_passwords = set()  # 使用set避免重复
        
        # 连接信号
        for checkbox in self.charset_checks.values():
            checkbox.toggled.connect(self.update_dict_preview)
        
        self.custom_charset_edit.textChanged.connect(self.update_dict_preview)
        self.min_length_spin.valueChanged.connect(self.update_dict_preview)
        self.max_length_spin.valueChanged.connect(self.update_dict_preview)
        
        for edit in [self.name_edit, self.birthday_edit, self.phone_edit, self.qq_edit, self.company_edit, self.hobby_edit]:
            edit.textChanged.connect(self.update_dict_preview)
        
        for checkbox in self.suffix_checks.values():
            checkbox.toggled.connect(self.update_dict_preview)
        
        self.year_checkbox.toggled.connect(self.toggle_year_controls)
        self.year_checkbox.toggled.connect(self.update_dict_preview)
        self.start_year_spin.valueChanged.connect(self.update_dict_preview)
        self.end_year_spin.valueChanged.connect(self.update_dict_preview)
        
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
    
    def update_dict_preview(self):
        """更新字典预览信息"""
        try:
            # 计算基础字典大小
            basic_count = 0
            if self.basic_enable_check.isChecked():
                charset = ""
                if self.charset_checks['lowercase'].isChecked():
                    charset += "abcdefghijklmnopqrstuvwxyz"
                if self.charset_checks['uppercase'].isChecked():
                    charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if self.charset_checks['digits'].isChecked():
                    charset += "0123456789"
                if self.charset_checks['symbols'].isChecked():
                    charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
                custom_chars = self.custom_charset_edit.text().strip()
                if custom_chars:
                    charset += custom_chars
                
                min_len = self.min_length_spin.value()
                max_len = self.max_length_spin.value()
                
                # 确保最小长度不大于最大长度
                if min_len > max_len:
                    self.max_length_spin.setValue(min_len)
                    max_len = min_len
                
                if charset:
                    charset_len = len(set(charset))  # 去重
                    for length in range(min_len, max_len + 1):
                        basic_count += charset_len ** length
            
            # 计算社工字典大小
            social_count = self.calculate_social_dict_size() if self.social_enable_check.isChecked() else 0
            
            # 计算手动添加的密码数量
            manual_count = 0
            if self.manual_enable_check.isChecked() and hasattr(self, 'manual_passwords'):
                manual_count = len(self.manual_passwords)
            
            total_count = basic_count + social_count + manual_count
            
            # 使用更精确的文件大小估算
            estimated_size = self._calculate_estimated_file_size()
            
            # 格式化显示
            if estimated_size < 1024:
                size_str = f"{estimated_size:.0f} B"
            elif estimated_size < 1024 * 1024:
                size_str = f"{estimated_size / 1024:.1f} KB"
            elif estimated_size < 1024 * 1024 * 1024:
                size_str = f"{estimated_size / (1024 * 1024):.1f} MB"
            else:
                size_str = f"{estimated_size / (1024 * 1024 * 1024):.1f} GB"
            
            # 格式化条数显示
            if total_count < 1000:
                count_str = str(total_count)
            elif total_count < 1000000:
                count_str = f"{total_count / 1000:.1f}K"
            elif total_count < 1000000000:
                count_str = f"{total_count / 1000000:.1f}M"
            else:
                count_str = f"{total_count / 1000000000:.1f}B"
            
            # 检查是否超过1GB阈值
            size_limit_gb = 1.0
            size_limit_bytes = size_limit_gb * 1024 * 1024 * 1024
            
            if estimated_size > size_limit_bytes:
                warning_text = f"预计条数: {count_str} | 预计大小: {size_str} ⚠️ 超过1GB阈值！"
                self.dict_info_label.setText(warning_text)
                self.dict_info_label.setStyleSheet("color: red; font-weight: bold; background-color: #ffe6e6; padding: 2px;")
            else:
                self.dict_info_label.setText(f"预计条数: {count_str} | 预计大小: {size_str}")
                
                # 根据大小设置颜色
                if total_count > 10000000:  # 超过1000万条
                    self.dict_info_label.setStyleSheet("color: red; font-weight: bold;")
                elif total_count > 1000000:  # 超过100万条
                    self.dict_info_label.setStyleSheet("color: orange; font-weight: bold;")
                else:
                    self.dict_info_label.setStyleSheet("color: blue; font-weight: bold;")
                
        except Exception as e:
            function_logger.error(f"更新字典预览失败: {e}")
            self.dict_info_label.setText("预计条数: 计算错误 | 预计大小: 未知")
            self.dict_info_label.setStyleSheet("color: red; font-weight: bold;")
    
    def calculate_social_dict_size(self):
        """计算社工字典大小"""
        social_count = 0
        
        # 收集所有信息
        all_info = []
        
        name = self.name_edit.text().strip()
        if name:
            name_variants = self.process_chinese_name(name)
            all_info.extend(name_variants)
        
        birthday = self.birthday_edit.text().strip()
        if birthday:
            all_info.append(birthday)
            # 添加生日的各种变形
            if len(birthday) == 8:  # YYYYMMDD格式
                all_info.extend([birthday[2:], birthday[4:], birthday[6:]])
            elif len(birthday) == 4:  # MMDD格式
                all_info.append(birthday)
        
        phone = self.phone_edit.text().strip()
        if phone:
            all_info.append(phone)
            if len(phone) == 11:  # 手机号
                all_info.extend([phone[3:], phone[7:], phone[-4:]])
        
        qq = self.qq_edit.text().strip()
        if qq:
            all_info.append(qq)
        
        company = self.company_edit.text().strip()
        if company:
            # 对于中文公司名，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in company):
                company_variants = self.process_chinese_name(company)
                all_info.extend(company_variants)
            else:
                all_info.extend([company, company.lower(), company.upper()])
        
        hobby = self.hobby_edit.text().strip()
        if hobby:
            # 对于中文爱好，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in hobby):
                hobby_variants = self.process_chinese_name(hobby)
                all_info.extend(hobby_variants)
            else:
                all_info.extend([hobby, hobby.lower(), hobby.upper()])
        
        # 年份
        years = []
        if self.year_checkbox.isChecked():
            for year in range(self.start_year_spin.value(), self.end_year_spin.value() + 1):
                years.extend([str(year), str(year)[2:]])
        
        # 后缀
        suffixes = []
        for suffix, checkbox in self.suffix_checks.items():
            if checkbox.isChecked():
                suffixes.append(suffix)
        
        # 计算组合数量
        if all_info:
            unique_all_info = list(set(all_info))
            total_unique_count = len(unique_all_info)
            
            # 基础信息
            social_count += total_unique_count
            
            # 信息 + 年份（双向组合）
            if years:
                social_count += total_unique_count * len(years) * 2  # info+year 和 year+info
            
            # 信息 + 后缀
            social_count += total_unique_count * len(suffixes)
            
            # 信息 + 年份 + 后缀（双向组合）
            if years:
                social_count += total_unique_count * len(years) * len(suffixes) * 2  # info+year+suffix 和 year+info+suffix
            
            # 年份 + 后缀（双向组合）
            if years:
                social_count += len(years) * len(suffixes) * 2  # year+suffix 和 suffix+year
            
            # 双信息组合（避免同一来源信息的重复组合）
            # 分离名字信息和其他信息
            name_count = 0
            other_count = 0
            
            if name:
                name_variants = self.process_chinese_name(name)
                name_count = len(set(name_variants))
            
            # 计算其他信息数量（生日、电话、QQ、公司、爱好）
            other_info_count = total_unique_count - name_count
            
            # 名字信息与其他信息的组合
            if name_count > 0 and other_info_count > 0:
                social_count += name_count * other_info_count * 2  # name+other 和 other+name
            
            # 其他信息之间的组合（估算，排除同源信息）
            if other_info_count > 1:
                # 保守估计，减少同源信息组合
                estimated_combinations = max(0, other_info_count * (other_info_count - 1) // 2 - 3)
                social_count += estimated_combinations * 2  # info1+info2 和 info2+info1
        
        return social_count
    
    def _calculate_estimated_file_size(self):
        """计算预估的字典文件大小（字节）"""
        try:
            # 计算基础字典大小
            basic_count = 0
            avg_basic_length = 0
            
            if self.basic_enable_check.isChecked():
                charset = ""
                if self.charset_checks['lowercase'].isChecked():
                    charset += "abcdefghijklmnopqrstuvwxyz"
                if self.charset_checks['uppercase'].isChecked():
                    charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if self.charset_checks['digits'].isChecked():
                    charset += "0123456789"
                if self.charset_checks['symbols'].isChecked():
                    charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
                custom_chars = self.custom_charset_edit.text().strip()
                if custom_chars:
                    charset += custom_chars
                
                min_len = self.min_length_spin.value()
                max_len = self.max_length_spin.value()
                
                if charset:
                    charset_len = len(set(charset))  # 去重
                    
                    # 对于固定长度的情况（如8位纯数字），直接计算
                    if min_len == max_len:
                        basic_count = charset_len ** min_len
                        avg_basic_length = min_len
                    else:
                        total_length = 0
                        for length in range(min_len, max_len + 1):
                            count_for_length = charset_len ** length
                            basic_count += count_for_length
                            total_length += count_for_length * length
                        
                        if basic_count > 0:
                            avg_basic_length = total_length / basic_count
                        else:
                            avg_basic_length = (min_len + max_len) / 2
            
            # 计算社工字典大小
            social_count = self.calculate_social_dict_size() if self.social_enable_check.isChecked() else 0
            avg_social_length = 10  # 假设社工字典平均长度为10个字符
            
            # 计算手动添加的密码数量
            manual_count = 0
            avg_manual_length = 8
            if self.manual_enable_check.isChecked() and hasattr(self, 'manual_passwords'):
                manual_count = len(self.manual_passwords)
                if manual_count > 0:
                    total_manual_length = sum(len(pwd) for pwd in self.manual_passwords)
                    avg_manual_length = total_manual_length / manual_count
            
            # 计算总的预估大小（每行额外加1字节用于换行符）
            estimated_size = (
                basic_count * (avg_basic_length + 1) +
                social_count * (avg_social_length + 1) +
                manual_count * (avg_manual_length + 1)
            )
            
            return estimated_size
            
        except Exception as e:
            function_logger.error(f"计算预估文件大小失败: {e}")
            return 0
    
    def preview_dictionary(self):
        """预览字典内容"""
        try:
            preview_lines = []
            max_preview = 50  # 最多预览50行
            
            # 生成基础字典样例
            if self.basic_enable_check.isChecked():
                charset = ""
                if self.charset_checks['lowercase'].isChecked():
                    charset += "abcdefghijklmnopqrstuvwxyz"
                if self.charset_checks['uppercase'].isChecked():
                    charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if self.charset_checks['digits'].isChecked():
                    charset += "0123456789"
                if self.charset_checks['symbols'].isChecked():
                    charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
                custom_chars = self.custom_charset_edit.text().strip()
                if custom_chars:
                    charset += custom_chars
                
                if charset:
                    charset = ''.join(set(charset))  # 去重
                    min_len = self.min_length_spin.value()
                    
                    # 生成一些基础字典样例
                    import itertools
                    count = 0
                    for length in range(min_len, min(min_len + 3, self.max_length_spin.value() + 1)):
                        for combo in itertools.product(charset, repeat=length):
                            if count >= max_preview // 2:
                                break
                            preview_lines.append(''.join(combo))
                            count += 1
                        if count >= max_preview // 2:
                            break
            
            # 生成社工字典样例
            if self.social_enable_check.isChecked():
                remaining_preview = max_preview - len(preview_lines)
                social_samples = self.generate_social_samples(remaining_preview // 2 if remaining_preview > 0 else 0)
                preview_lines.extend(social_samples)
            
            # 添加手动密码样例
            if self.manual_enable_check.isChecked() and hasattr(self, 'manual_passwords') and self.manual_passwords:
                remaining_preview = max_preview - len(preview_lines)
                if remaining_preview > 0:
                    manual_samples = list(self.manual_passwords)[:remaining_preview]
                    if manual_samples:
                        preview_lines.append("\n--- 手动添加的密码 ---")
                        preview_lines.extend(manual_samples)
            
            if preview_lines:
                self.preview_text.setPlainText('\n'.join(preview_lines[:max_preview]))
                if len(preview_lines) >= max_preview:
                    current_text = self.preview_text.toPlainText()
                    self.preview_text.setPlainText(current_text + "\n\n... (仅显示前50行样例)")
            else:
                self.preview_text.setPlainText("请先配置字典生成参数")
                
        except Exception as e:
            function_logger.error(f"预览字典失败: {e}")
            self.preview_text.setPlainText(f"预览失败: {str(e)}")
    
    def generate_social_samples(self, max_count):
        """生成社工字典样例"""
        samples = []
        
        # 收集所有信息
        all_info = []
        
        name = self.name_edit.text().strip()
        if name:
            name_variants = self.process_chinese_name(name)
            all_info.extend(name_variants)
        
        birthday = self.birthday_edit.text().strip()
        if birthday:
            all_info.append(birthday)
            # 添加生日的各种变形
            if len(birthday) == 8:  # YYYYMMDD格式
                all_info.extend([birthday[2:], birthday[4:], birthday[6:]])
            elif len(birthday) == 4:  # MMDD格式
                all_info.append(birthday)
        
        phone = self.phone_edit.text().strip()
        if phone:
            all_info.append(phone)
            if len(phone) == 11:  # 手机号
                all_info.extend([phone[3:], phone[7:], phone[-4:]])
        
        qq = self.qq_edit.text().strip()
        if qq:
            all_info.append(qq)
        
        company = self.company_edit.text().strip()
        if company:
            # 对于中文公司名，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in company):
                company_variants = self.process_chinese_name(company)
                all_info.extend(company_variants)
            else:
                all_info.extend([company, company.lower(), company.upper()])
        
        hobby = self.hobby_edit.text().strip()
        if hobby:
            # 对于中文爱好，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in hobby):
                hobby_variants = self.process_chinese_name(hobby)
                all_info.extend(hobby_variants)
            else:
                all_info.extend([hobby, hobby.lower(), hobby.upper()])
        
        # 年份样例（取前几个和后几个）
        years = []
        if self.year_checkbox.isChecked():
            start_year = self.start_year_spin.value()
            end_year = self.end_year_spin.value()
            for year in range(start_year, min(start_year + 3, end_year + 1)):
                years.extend([str(year), str(year)[2:]])
            if end_year > start_year + 2:
                for year in range(max(end_year - 2, start_year + 3), end_year + 1):
                    years.extend([str(year), str(year)[2:]])
        
        # 后缀样例
        suffixes = []
        for suffix, checkbox in self.suffix_checks.items():
            if checkbox.isChecked():
                suffixes.append(suffix)
        
        # 生成组合样例，按照实际生成逻辑
        count = 0
        
        # 去重信息列表
        unique_all_info = list(set(all_info))
        
        if unique_all_info:
            # 基础信息
            for info in unique_all_info[:min(5, max_count)]:
                if count >= max_count:
                    break
                samples.append(info)
                count += 1
            
            # 信息 + 年份
            for info in unique_all_info[:3]:
                for year in years[:3]:
                    if count >= max_count:
                        break
                    samples.append(info + year)
                    count += 1
                if count >= max_count:
                    break
            
            # 信息 + 后缀
            for info in unique_all_info[:3]:
                for suffix in suffixes[:3]:
                    if count >= max_count:
                        break
                    samples.append(info + suffix)
                    count += 1
                if count >= max_count:
                    break
            
            # 信息 + 年份 + 后缀
            for info in unique_all_info[:2]:
                for year in years[:2]:
                    for suffix in suffixes[:2]:
                        if count >= max_count:
                            break
                        samples.append(info + year + suffix)
                        count += 1
                    if count >= max_count:
                        break
                if count >= max_count:
                    break
            
            # 双信息组合样本（避免同一来源信息的重复组合）
            # 分离名字信息和其他信息
            sample_name_info = []
            sample_other_info = []
            
            if name:
                name_variants = self.process_chinese_name(name)
                sample_name_info = list(set(name_variants))[:3]  # 取前3个名字变体
            
            # 其他信息（排除名字信息）
            for info in unique_all_info:
                if info not in sample_name_info:
                    sample_other_info.append(info)
            sample_other_info = sample_other_info[:3]  # 取前3个其他信息
            
            # 名字信息与其他信息的组合
            for name_variant in sample_name_info:
                for other in sample_other_info:
                    if count >= max_count:
                        break
                    samples.append(name_variant + other)
                    count += 1
                    if count >= max_count:
                        break
                    samples.append(other + name_variant)
                    count += 1
                if count >= max_count:
                    break
            
            # 其他信息之间的组合（简化，只取少量样本）
            if len(sample_other_info) > 1:
                for i, info1 in enumerate(sample_other_info[:2]):
                    for info2 in sample_other_info[i+1:2]:
                        if count >= max_count:
                            break
                        samples.append(info1 + info2)
                        count += 1
                    if count >= max_count:
                        break
        
        # 年份 + 后缀
        for year in years[:3]:
            for suffix in suffixes[:3]:
                if count >= max_count:
                    break
                samples.append(year + suffix)
                count += 1
            if count >= max_count:
                break
        
        return samples[:max_count]
    
    def generate_dictionary(self):
        """生成字典文件"""
        try:
            filename = self.filename_edit.text().strip()
            if not filename:
                QMessageBox.warning(self, "警告", "请输入文件名")
                return
            
            if not filename.endswith('.txt'):
                filename += '.txt'
            
            # 检查预计文件大小是否超过1GB阈值
            estimated_size = self._calculate_estimated_file_size()
            size_limit_gb = 1.0  # 1GB阈值
            size_limit_bytes = size_limit_gb * 1024 * 1024 * 1024
            
            if estimated_size > size_limit_bytes:
                size_gb = estimated_size / (1024 * 1024 * 1024)
                reply = QMessageBox.warning(self, "警告", 
                    f"预计生成的字典文件大小约为 {size_gb:.2f} GB，超过了 {size_limit_gb} GB 的安全阈值。\n\n"
                    f"生成如此大的字典可能会：\n"
                    f"• 占用大量磁盘空间\n"
                    f"• 消耗大量内存和CPU资源\n"
                    f"• 导致程序响应缓慢或崩溃\n\n"
                    f"建议：\n"
                    f"• 减少字符集范围\n"
                    f"• 降低最大密码长度\n"
                    f"• 减少社工字典的信息输入\n\n"
                    f"是否仍要继续生成？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No)
                if reply != QMessageBox.Yes:
                    return
            
            # 创建dic目录
            import os
            dic_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dic')
            os.makedirs(dic_dir, exist_ok=True)
            
            filepath = os.path.join(dic_dir, filename)
            
            # 检查文件是否存在
            if os.path.exists(filepath):
                reply = QMessageBox.question(self, "确认", f"文件 {filename} 已存在，是否覆盖？",
                                           QMessageBox.Yes | QMessageBox.No)
                if reply != QMessageBox.Yes:
                    return
            
            # 显示进度对话框
            progress = QProgressDialog("正在生成字典...", "取消", 0, 100, self)
            progress.setWindowTitle("生成字典")
            progress.setWindowModality(Qt.WindowModal)
            # 设置窗口图标，避免显示？图标
            if hasattr(self, 'windowIcon') and not self.windowIcon().isNull():
                progress.setWindowIcon(self.windowIcon())
            progress.show()
            
            QApplication.processEvents()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                written_count = 0
                
                # 生成基础字典
                if self.basic_enable_check.isChecked():
                    charset = ""
                    if self.charset_checks['lowercase'].isChecked():
                        charset += "abcdefghijklmnopqrstuvwxyz"
                    if self.charset_checks['uppercase'].isChecked():
                        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    if self.charset_checks['digits'].isChecked():
                        charset += "0123456789"
                    if self.charset_checks['symbols'].isChecked():
                        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                    
                    custom_chars = self.custom_charset_edit.text().strip()
                    if custom_chars:
                        charset += custom_chars
                    
                    if charset:
                        charset = ''.join(set(charset))  # 去重
                        min_len = self.min_length_spin.value()
                        max_len = self.max_length_spin.value()
                        
                        import itertools
                        total_basic = sum(len(charset) ** length for length in range(min_len, max_len + 1))
                        current_basic = 0
                        
                        for length in range(min_len, max_len + 1):
                            for combo in itertools.product(charset, repeat=length):
                                if progress.wasCanceled():
                                    f.close()
                                    os.remove(filepath)
                                    return
                                
                                f.write(''.join(combo) + '\n')
                                written_count += 1
                                current_basic += 1
                                
                                if current_basic % 1000 == 0:
                                    progress.setValue(int(40 * current_basic / total_basic))
                                    QApplication.processEvents()
                        
                        # 基础字典生成完成，设置进度为40%
                        progress.setValue(40)
                
                else:
                    # 如果没有启用基础字典，直接设置进度为40%
                    progress.setValue(40)
                QApplication.processEvents()
                
                # 生成社工字典
                if self.social_enable_check.isChecked():
                    social_passwords = self.generate_social_passwords()
                    total_social = len(social_passwords)
                    
                    for i, password in enumerate(social_passwords):
                        if progress.wasCanceled():
                            f.close()
                            os.remove(filepath)
                            return
                        
                        f.write(password + '\n')
                        written_count += 1
                        
                        if i % 100 == 0:
                            progress.setValue(40 + int(40 * i / max(total_social, 1)))
                            QApplication.processEvents()
                
                progress.setValue(80)
                QApplication.processEvents()
                
                # 添加手动输入的密码
                if self.manual_enable_check.isChecked() and hasattr(self, 'manual_passwords'):
                    manual_count = len(self.manual_passwords)
                    for i, password in enumerate(self.manual_passwords):
                        if progress.wasCanceled():
                            f.close()
                            os.remove(filepath)
                            return
                        
                        f.write(password + '\n')
                        written_count += 1
                        
                        if manual_count > 0 and i % 10 == 0:
                            progress.setValue(80 + int(20 * i / manual_count))
                            QApplication.processEvents()
            
            progress.setValue(100)
            progress.close()
            
            # 获取文件大小
            file_size = os.path.getsize(filepath)
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            else:
                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
            
            QMessageBox.information(self, "成功", 
                                  f"字典生成完成！\n\n"
                                  f"文件路径: {filepath}\n"
                                  f"总条数: {written_count:,}\n"
                                  f"文件大小: {size_str}")
            
        except Exception as e:
            function_logger.error(f"生成字典失败: {e}")
            QMessageBox.critical(self, "错误", f"生成字典失败: {str(e)}")
    
    def generate_social_passwords(self):
        """生成社工字典密码列表"""
        passwords = set()  # 使用set去重
        
        # 收集所有信息
        all_info = []
        
        name = self.name_edit.text().strip()
        if name:
            name_variants = self.process_chinese_name(name)
            all_info.extend(name_variants)
        
        birthday = self.birthday_edit.text().strip()
        if birthday:
            all_info.append(birthday)
            # 生日变形
            if len(birthday) == 8:  # YYYYMMDD
                all_info.extend([birthday[2:], birthday[4:], birthday[6:]])
            elif len(birthday) == 4:  # MMDD
                all_info.append(birthday)
        
        phone = self.phone_edit.text().strip()
        if phone:
            all_info.append(phone)
            if len(phone) == 11:  # 手机号变形
                all_info.extend([phone[3:], phone[7:], phone[-4:]])
        
        qq = self.qq_edit.text().strip()
        if qq:
            all_info.append(qq)
        
        company = self.company_edit.text().strip()
        if company:
            # 对于中文公司名，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in company):
                company_variants = self.process_chinese_name(company)
                all_info.extend(company_variants)
            else:
                all_info.extend([company, company.lower(), company.upper()])
        
        hobby = self.hobby_edit.text().strip()
        if hobby:
            # 对于中文爱好，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in hobby):
                hobby_variants = self.process_chinese_name(hobby)
                all_info.extend(hobby_variants)
            else:
                all_info.extend([hobby, hobby.lower(), hobby.upper()])
        
        # 年份列表
        years = []
        if self.year_checkbox.isChecked():
            for year in range(self.start_year_spin.value(), self.end_year_spin.value() + 1):
                years.extend([str(year), str(year)[2:]])
        
        # 后缀列表
        suffixes = []
        for suffix, checkbox in self.suffix_checks.items():
            if checkbox.isChecked():
                suffixes.append(suffix)
        
        # 生成密码组合
        # 1. 基础信息
        for info in all_info:
            if info:
                passwords.add(info)
        
        # 2. 信息 + 年份
        for info in all_info:
            for year in years:
                if info:
                    passwords.add(info + year)
                    passwords.add(year + info)
        
        # 3. 信息 + 后缀
        for info in all_info:
            for suffix in suffixes:
                if info:
                    passwords.add(info + suffix)
        
        # 4. 信息 + 年份 + 后缀
        for info in all_info:
            for year in years:
                for suffix in suffixes:
                    if info:
                        passwords.add(info + year + suffix)
                        passwords.add(year + info + suffix)
        
        # 5. 年份 + 后缀
        for year in years:
            for suffix in suffixes:
                passwords.add(year + suffix)
                passwords.add(suffix + year)
        
        # 6. 双信息组合（避免同一来源信息的重复组合）
        # 分离不同来源的信息
        name_info = []
        other_info = []
        
        # 重新分类信息，避免名字变体之间的组合
        if name:
            name_variants = self.process_chinese_name(name)
            name_info.extend(name_variants)
        
        # 其他信息（生日、电话、QQ、公司、爱好）
        if birthday:
            other_info.append(birthday)
            if len(birthday) == 8:
                other_info.extend([birthday[2:], birthday[4:], birthday[6:]])
            elif len(birthday) == 4:
                other_info.append(birthday)
        
        if phone:
            other_info.append(phone)
            if len(phone) == 11:
                other_info.extend([phone[3:], phone[7:], phone[-4:]])
        
        if qq:
            other_info.append(qq)
        
        if company:
            # 对于中文公司名，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in company):
                company_variants = self.process_chinese_name(company)
                other_info.extend(company_variants)
            else:
                other_info.extend([company, company.lower(), company.upper()])
        
        if hobby:
            # 对于中文爱好，转换为拼音
            if any('\u4e00' <= char <= '\u9fff' for char in hobby):
                hobby_variants = self.process_chinese_name(hobby)
                other_info.extend(hobby_variants)
            else:
                other_info.extend([hobby, hobby.lower(), hobby.upper()])
        
        # 只允许名字信息与其他信息组合，避免名字变体之间的组合
        for name_variant in name_info:
            for other in other_info:
                if name_variant and other and name_variant != other:
                    passwords.add(name_variant + other)
                    passwords.add(other + name_variant)
        
        # 其他信息之间的组合（排除同类型信息）
        for i, info1 in enumerate(other_info):
            for info2 in other_info[i+1:]:
                if info1 and info2 and info1 != info2:
                    # 避免同一来源的信息组合（如生日的不同变形）
                    if not self._is_same_source_info(info1, info2, birthday, phone):
                        passwords.add(info1 + info2)
                        passwords.add(info2 + info1)
        
        return list(passwords)
    
    def _is_same_source_info(self, info1, info2, birthday, phone):
        """判断两个信息是否来自同一来源"""
        # 检查是否都是生日相关信息
        if birthday:
            birthday_variants = [birthday]
            if len(birthday) == 8:
                birthday_variants.extend([birthday[2:], birthday[4:], birthday[6:]])
            elif len(birthday) == 4:
                birthday_variants.append(birthday)
            
            if info1 in birthday_variants and info2 in birthday_variants:
                return True
        
        # 检查是否都是电话相关信息
        if phone and len(phone) == 11:
            phone_variants = [phone, phone[3:], phone[7:], phone[-4:]]
            if info1 in phone_variants and info2 in phone_variants:
                return True
        
        return False
    
    def add_manual_password(self):
        """添加手动输入的密码"""
        password = self.manual_password_edit.text().strip()
        if not password:
            QMessageBox.warning(self, "警告", "请输入密码")
            return
        
        if password in self.manual_passwords:
            QMessageBox.information(self, "提示", "该密码已存在")
            return
        
        # 添加到集合中
        self.manual_passwords.add(password)
        
        # 更新显示
        self.update_manual_passwords_display()
        
        # 清空输入框
        self.manual_password_edit.clear()
        
        # 更新字典预览信息
        self.update_dict_preview()
    
    def clear_manual_passwords(self):
        """清空手动添加的密码列表"""
        if not self.manual_passwords:
            return
        
        reply = QMessageBox.question(self, "确认", "确定要清空所有手动添加的密码吗？",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.manual_passwords.clear()
            self.update_manual_passwords_display()
            self.update_dict_preview()
    
    def import_manual_passwords(self):
        """从文件导入密码"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择密码文件", "", "文本文件 (*.txt);;所有文件 (*.*)")
        if not file_path:
            return
        
        try:
            imported_count = 0
            duplicate_count = 0
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password:  # 忽略空行
                        if password in self.manual_passwords:
                            duplicate_count += 1
                        else:
                            self.manual_passwords.add(password)
                            imported_count += 1
            
            self.update_manual_passwords_display()
            self.update_dict_preview()
            
            message = f"导入完成！\n\n新增密码: {imported_count} 条"
            if duplicate_count > 0:
                message += f"\n重复密码: {duplicate_count} 条（已跳过）"
            
            QMessageBox.information(self, "导入结果", message)
            
        except Exception as e:
            function_logger.error(f"导入密码文件失败: {e}")
            QMessageBox.critical(self, "错误", f"导入失败: {str(e)}")
    
    def update_manual_passwords_display(self):
        """更新手动密码显示"""
        if self.manual_passwords:
            # 按添加顺序显示（转换为列表并排序）
            password_list = sorted(list(self.manual_passwords))
            display_text = '\n'.join(password_list)
            
            # 如果密码太多，只显示前100个
            if len(password_list) > 100:
                display_list = password_list[:100]
                display_text = '\n'.join(display_list)
                display_text += f"\n\n... 还有 {len(password_list) - 100} 条密码未显示"
            
            self.manual_passwords_list.setPlainText(display_text)
        else:
            self.manual_passwords_list.setPlainText("")
        
        # 更新计数标签
        count = len(self.manual_passwords)
        self.manual_count_label.setText(f"手动添加: {count} 条")
        
        # 根据数量设置颜色
        if count == 0:
            self.manual_count_label.setStyleSheet("color: gray; font-weight: bold;")
        elif count < 100:
            self.manual_count_label.setStyleSheet("color: green; font-weight: bold;")
        elif count < 1000:
            self.manual_count_label.setStyleSheet("color: orange; font-weight: bold;")
        else:
            self.manual_count_label.setStyleSheet("color: red; font-weight: bold;")
    
    def toggle_basic_controls(self, checked):
        """切换基础字典生成控件的启用状态"""
        self.min_length_spin.setEnabled(checked)
        self.max_length_spin.setEnabled(checked)
        for checkbox in self.charset_checks.values():
            checkbox.setEnabled(checked)
        self.custom_charset_edit.setEnabled(checked)
        self.update_dict_preview()
    
    def toggle_social_controls(self, checked):
        """切换社工字典生成控件的启用状态"""
        self.name_edit.setEnabled(checked)
        self.birthday_edit.setEnabled(checked)
        self.phone_edit.setEnabled(checked)
        self.qq_edit.setEnabled(checked)
        self.company_edit.setEnabled(checked)
        self.hobby_edit.setEnabled(checked)
        for checkbox in self.suffix_checks.values():
            checkbox.setEnabled(checked)
        self.year_checkbox.setEnabled(checked)
        # 年份控件的启用状态由年份复选框控制
        if checked and self.year_checkbox.isChecked():
            self.start_year_spin.setEnabled(True)
            self.end_year_spin.setEnabled(True)
        else:
            self.start_year_spin.setEnabled(False)
            self.end_year_spin.setEnabled(False)
        self.update_dict_preview()
    
    def toggle_year_controls(self, checked):
        """切换年份控件的启用状态"""
        # 只有在社工字典启用时才能控制年份控件
        if self.social_enable_check.isChecked():
            self.start_year_spin.setEnabled(checked)
            self.end_year_spin.setEnabled(checked)
    
    def toggle_manual_controls(self, checked):
        """切换手动添加控件的启用状态"""
        self.manual_password_edit.setEnabled(checked)
        self.add_password_btn.setEnabled(checked)
        self.manual_passwords_list.setEnabled(checked)
        self.clear_manual_btn.setEnabled(checked)
        self.import_manual_btn.setEnabled(checked)
        self.update_dict_preview()
    
    def create_help_tab(self):
        """创建帮助文档标签页"""
        function_logger.debug("HashcatGUI.create_help_tab called")
        help_widget = QWidget()
        self.tab_widget.addTab(help_widget, "帮助文档")
        
        layout = QVBoxLayout(help_widget)
        
        # 帮助文档内容
        self.help_text = QTextEdit()
        self.help_text.setReadOnly(True)
        self.load_help_content()
        layout.addWidget(self.help_text)
    
    def setup_signals(self):
        """设置所有信号连接"""
        function_logger.debug("HashcatGUI.setup_signals called")
        # 解密类型切换信号
        self.file_radio.toggled.connect(self.on_decrypt_type_changed)
        self.text_radio.toggled.connect(self.on_decrypt_type_changed)
        self.batch_radio.toggled.connect(self.on_decrypt_type_changed)
        
        # 攻击模式变化信号
        self.attack_mode_combo.currentTextChanged.connect(self.on_attack_mode_changed)
        
        # 命令预览更新信号
        self.hash_edit.textChanged.connect(self.update_command_preview)
        self.hash_type_combo.currentTextChanged.connect(self.on_hash_type_changed)
        self.workload_combo.currentTextChanged.connect(self.update_command_preview)
        self.mask_edit.textChanged.connect(self.update_command_preview)
        self.charset1_edit.textChanged.connect(self.update_command_preview)
        self.charset2_edit.textChanged.connect(self.update_command_preview)
        self.charset3_edit.textChanged.connect(self.update_command_preview)
        self.charset4_edit.textChanged.connect(self.update_command_preview)
        self.dict_path_edit.textChanged.connect(self.update_command_preview)
        
        # 增量设置信号
        self.increment_check.toggled.connect(self.update_command_preview)
        self.min_len_edit.textChanged.connect(self.update_command_preview)
        self.max_len_edit.textChanged.connect(self.update_command_preview)
        
        # 其他选项信号
        self.show_potfile_check.toggled.connect(self.on_show_potfile_toggled)
        self.quiet_check.toggled.connect(self.update_command_preview)
        self.force_check.toggled.connect(self.update_command_preview)
        
        # 输出设置信号
        self.output_file_edit.textChanged.connect(self.update_command_preview)
        self.output_format_combo.currentTextChanged.connect(self.update_command_preview)
        
        # 初始化设备相关变量
        self.device_checkboxes = []
        
        # 设备选择信号
        self.manual_device_edit.textChanged.connect(self.update_command_preview)
        self.refresh_devices_btn.clicked.connect(self.refresh_device_list)
        self.select_all_devices_btn.clicked.connect(self.select_all_devices)
        self.deselect_all_devices_btn.clicked.connect(self.deselect_all_devices)
        
        # 路径编辑框信号
        self.john_path_edit.textChanged.connect(lambda: self.validate_john_path(self.john_path_edit.text()))
        self.hashcat_path_edit.textChanged.connect(self._on_hashcat_path_changed)
        
        # 新增控件信号连接
        self.mask_template_combo.currentTextChanged.connect(self.on_mask_template_changed)
        
        # 性能设置信号
        self.kernel_loops_edit.textChanged.connect(self.update_command_preview)
        self.kernel_threads_edit.textChanged.connect(self.update_command_preview)
        self.optimized_kernel_check.toggled.connect(self.update_command_preview)
        
        # 安全选项信号
        self.temp_abort_edit.textChanged.connect(self.update_command_preview)
        self.runtime_edit.textChanged.connect(self.update_command_preview)
        self.status_timer_edit.textChanged.connect(self.update_command_preview)
    
    def on_decrypt_type_changed(self):
        """解密类型改变时的处理"""
        function_logger.debug("HashcatGUI.on_decrypt_type_changed called")
        is_file_mode = self.file_radio.isChecked()
        is_text_mode = self.text_radio.isChecked()
        is_batch_mode = self.batch_radio.isChecked()
        
        # 显示/隐藏相应控件
        self.file_label.setVisible(is_file_mode)
        self.file_path_edit.setVisible(is_file_mode)
        self.browse_file_btn.setVisible(is_file_mode)
        
        self.hash_label.setVisible(is_text_mode)
        self.hash_edit.setVisible(is_text_mode)
        
        self.batch_label.setVisible(is_batch_mode)
        self.batch_path_edit.setVisible(is_batch_mode)
        self.browse_batch_btn.setVisible(is_batch_mode)
        
        # 更新命令预览
        self.update_command_preview()
    
    def browse_file(self):
        """浏览文件"""
        function_logger.debug("HashcatGUI.browse_file called")
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择要破解的文件", "", 
            "所有支持的文件 (*.zip *.rar *.7z *.doc *.docx *.xls *.xlsx *.ppt *.pptx *.pdf *.odt *.ods *.odp *.odg *.odf *.kdbx *.kdb *.psafe3 *.enpassdb *.walletx *.db *.dat *.wallet *.json *.keystore *.multibit *.electrum *.key *.numbers *.pages *.plist *.keychain *.dmg *.tc *.hc *.luks *.img *.axx *.encfs6.xml *.id *.nsf *.key3.db *.key4.db *.xml *.sxc *.sxw *.sxi *.sxd *.loop *.seco *.metamask *.vc *.vdi *.vmx *.aes *.v2 *.notes);;"
            "压缩文件 (*.zip *.rar *.7z);;"
            "Office文档 (*.doc *.docx *.xls *.xlsx *.ppt *.pptx);;"
            "PDF文件 (*.pdf);;"
            "OpenDocument文件 (*.odt *.ods *.odp *.odg *.odf);;"
            "StarOffice文件 (*.sxc *.sxw *.sxi *.sxd);;"
            "密码管理器 (*.kdbx *.kdb *.psafe3 *.enpassdb *.walletx *.db);;"
            "加密货币钱包 (*.dat *.wallet *.json *.keystore *.multibit *.electrum);;"
            "Apple文件 (*.key *.numbers *.pages *.plist *.keychain *.dmg);;"
            "磁盘加密 (*.tc *.hc *.luks *.img);;"
            "文件加密 (*.axx *.encfs6.xml);;"
            "应用程序 (*.id *.nsf *.key3.db *.key4.db *.xml);;"
            "Hashcat专用工具 (*.loop *.seco *.metamask *.vc *.vdi *.vmx *.aes *.v2 *.notes);;"
            "所有文件 (*.*)"
        )
        if file_path:
            self.file_path_edit.setText(file_path)
            
            # 定期清理缓存，避免内存占用过多
            self.clear_hash_cache()
            
            # 自动提取hash并选择对应的hash类型
            self.auto_detect_hash_type(file_path)
    
    def on_hash_type_changed(self):
        """处理用户手动更改哈希类型的事件"""
        function_logger.debug("HashcatGUI.on_hash_type_changed called")
        # 标记用户已手动选择哈希类型
        self._user_selected_hash_type = True
        # 更新命令预览
        self.update_command_preview()
    
    def auto_detect_hash_type(self, file_path):
        """自动检测并选择hash类型"""
        function_logger.debug(f"HashcatGUI.auto_detect_hash_type called with file_path: {file_path}")
        try:
            # 显示正在检测的状态
            self.log_text.append(f"正在检测文件类型: {os.path.basename(file_path)}")
            
            # 提取哈希和类型
            hash_value, hash_type_or_error = self.get_hash_from_file(file_path)
            
            if hash_value is None:
                self.log_text.append(f"检测失败: {hash_type_or_error}")
                return
            
            # 重置用户选择标记，因为这是自动检测
            self._user_selected_hash_type = False
            
            # 自动选择对应的hash类型
            for i in range(self.hash_type_combo.count()):
                if self.hash_type_combo.itemText(i).startswith(hash_type_or_error):
                    self.hash_type_combo.setCurrentIndex(i)
                    hash_type_name = self.hash_type_combo.itemText(i)
                    self.log_text.append(f"已自动选择hash类型: {hash_type_name}")
                    # 使用已提取的哈希值更新命令预览，避免重复调用get_hash_from_file
                    self._update_command_preview_with_hash(hash_value)
                    break
            else:
                self.log_text.append(f"未找到匹配的hash类型: {hash_type_or_error}")
                
        except Exception as e:
            self.log_text.append(f"自动检测hash类型时出错: {str(e)}")
    
    def browse_dict(self):
        """浏览字典文件"""
        function_logger.debug("HashcatGUI.browse_dict called")
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", 
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_path:
            self.dict_path_edit.setText(file_path)
            self.update_command_preview()
    
    def browse_john_path(self):
        """浏览John路径"""
        function_logger.debug("HashcatGUI.browse_john_path called")
        dir_path = QFileDialog.getExistingDirectory(
            self, "选择John the Ripper目录"
        )
        if dir_path:
            self.john_path_edit.setText(dir_path)
            self.validate_john_path(dir_path)
    
    def browse_hashcat_path(self):
        """浏览Hashcat路径"""
        function_logger.debug("HashcatGUI.browse_hashcat_path called")
        dir_path = QFileDialog.getExistingDirectory(
            self, "选择Hashcat目录"
        )
        if dir_path:
            self.hashcat_path_edit.setText(dir_path)
            self.validate_hashcat_path(dir_path)
    
    def validate_john_path(self, path):
        """验证John路径是否正确"""
        function_logger.debug(f"HashcatGUI.validate_john_path called with path: {path}")
        if not path.strip():
            self.config_status_label.setText("")
            return
        
        john_exe_path = None
        
        # 检查是否为john.exe文件路径
        if os.path.exists(path) and os.path.isfile(path):
            john_exe_path = path
        # 检查是否为包含john.exe的目录路径
        elif os.path.exists(path) and os.path.isdir(path):
            potential_john_path = os.path.join(path, Config.JOHN_EXE)
            if os.path.exists(potential_john_path):
                john_exe_path = potential_john_path
            else:
                self.config_status_label.setText(f"✗ John目录中未找到{Config.JOHN_EXE}")
                self.config_status_label.setStyleSheet("color: red;")
                return
        else:
            self.config_status_label.setText("✗ John路径不存在")
            self.config_status_label.setStyleSheet("color: red;")
            return
        
        # 验证john.exe是否可执行
        if john_exe_path:
            try:
                # 尝试运行john --help来验证
                # Windows下隐藏控制台窗口
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                result = subprocess.run([john_exe_path, "--help"], 
                                      capture_output=True, text=True, timeout=5, encoding='utf-8',
                                      creationflags=creation_flags)
                if result.returncode == 0 or "john" in result.stdout.lower() or "john" in result.stderr.lower():
                    self.config_status_label.setText("✓ John路径验证成功")
                    self.config_status_label.setStyleSheet("color: green;")
                else:
                    self.config_status_label.setText("⚠ John路径可能不正确")
                    self.config_status_label.setStyleSheet("color: orange;")
            except Exception as e:
                self.config_status_label.setText(f"⚠ John路径验证失败: {str(e)}")
                self.config_status_label.setStyleSheet("color: orange;")
    
    def validate_hashcat_path(self, path):
        """验证Hashcat路径是否正确"""
        function_logger.debug(f"HashcatGUI.validate_hashcat_path called with path: {path}")
        if not path.strip():
            self.config_status_label.setText("")
            return
        
        hashcat_exe_path = None
        
        # 检查是否为hashcat.exe文件路径
        if os.path.exists(path) and os.path.isfile(path):
            hashcat_exe_path = path
        # 检查是否为包含hashcat.exe的目录路径
        elif os.path.exists(path) and os.path.isdir(path):
            potential_hashcat_path = os.path.join(path, Config.HASHCAT_EXE)
            if os.path.exists(potential_hashcat_path):
                hashcat_exe_path = potential_hashcat_path
            else:
                self.config_status_label.setText(f"✗ Hashcat目录中未找到{Config.HASHCAT_EXE}")
                self.config_status_label.setStyleSheet("color: red;")
                return
        else:
            self.config_status_label.setText("✗ Hashcat路径不存在")
            self.config_status_label.setStyleSheet("color: red;")
            return
        
        # 验证hashcat.exe是否可执行
        if hashcat_exe_path:
            try:
                # 尝试运行hashcat --version来验证
                # Windows下隐藏控制台窗口
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                result = subprocess.run([hashcat_exe_path, "--version"], 
                                      capture_output=True, text=True, timeout=5, encoding='utf-8',
                                      creationflags=creation_flags)
                if result.returncode == 0:
                    version_info = result.stdout.strip() if result.stdout else result.stderr.strip()
                    self.config_status_label.setText(f"✓ Hashcat路径验证成功 ({version_info.split()[0] if version_info else 'Unknown version'})")
                    self.config_status_label.setStyleSheet("color: green;")
                else:
                    self.config_status_label.setText("⚠ Hashcat路径可能不正确")
                    self.config_status_label.setStyleSheet("color: orange;")
            except Exception as e:
                self.config_status_label.setText(f"⚠ Hashcat路径验证失败: {str(e)}")
                self.config_status_label.setStyleSheet("color: orange;")
    
    def on_attack_mode_changed(self):
        """攻击模式变化时的处理"""
        function_logger.debug("HashcatGUI.on_attack_mode_changed called")
        current_mode = self.attack_mode_combo.currentText()
        
        if "字典" in current_mode and "掩码" not in current_mode:
            # 字典攻击模式 - 启用字典，禁用掩码、自定义字符集和常用模板
            self.dict_label.setEnabled(True)
            self.dict_path_edit.setEnabled(True)
            self.browse_dict_btn.setEnabled(True)
            self.mask_label.setEnabled(False)
            self.mask_edit.setEnabled(False)
            self.mask_info.setEnabled(False)
            self.mask_generator_btn.setEnabled(False)
            # 禁用自定义字符集
            self.charset1_edit.setEnabled(False)
            self.charset2_edit.setEnabled(False)
            self.charset3_edit.setEnabled(False)
            self.charset4_edit.setEnabled(False)
            # 禁用常用模板
            self.mask_template_combo.setEnabled(False)
        elif "掩码" in current_mode and "字典" not in current_mode:
            # 掩码攻击模式 - 禁用字典，启用掩码、自定义字符集和常用模板
            self.dict_label.setEnabled(False)
            self.dict_path_edit.setEnabled(False)
            self.browse_dict_btn.setEnabled(False)
            self.mask_label.setEnabled(True)
            self.mask_edit.setEnabled(True)
            self.mask_info.setEnabled(True)
            self.mask_generator_btn.setEnabled(True)
            # 启用自定义字符集
            self.charset1_edit.setEnabled(True)
            self.charset2_edit.setEnabled(True)
            self.charset3_edit.setEnabled(True)
            self.charset4_edit.setEnabled(True)
            # 启用常用模板
            self.mask_template_combo.setEnabled(True)
        else:
            # 混合模式或其他 - 都启用
            self.dict_label.setEnabled(True)
            self.dict_path_edit.setEnabled(True)
            self.browse_dict_btn.setEnabled(True)
            self.mask_label.setEnabled(True)
            self.mask_edit.setEnabled(True)
            self.mask_info.setEnabled(True)
            self.mask_generator_btn.setEnabled(True)
            # 启用自定义字符集
            self.charset1_edit.setEnabled(True)
            self.charset2_edit.setEnabled(True)
            self.charset3_edit.setEnabled(True)
            self.charset4_edit.setEnabled(True)
            # 启用常用模板
            self.mask_template_combo.setEnabled(True)
        
        # 更新命令预览
        self.update_command_preview()
    
    def browse_output(self):
        """浏览输出文件"""
        function_logger.debug("HashcatGUI.browse_output called")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "选择输出文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self.output_file_edit.setText(file_path)
    
    def open_mask_generator(self):
        """打开掩码生成器对话框"""
        function_logger.debug("HashcatGUI.open_mask_generator called")
        dialog = MaskGeneratorDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            mask = dialog.get_mask()
            if mask:
                self.mask_edit.setText(mask)
            # 保存主界面配置（包括掩码设置）
            self.save_config()
    
    def load_config(self):
        function_logger.debug("HashcatGUI.load_config called")
        """加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.john_path = config.get('john_path', self.john_path)
                    self.hashcat_path = config.get('hashcat_path', self.hashcat_path)
                    # 加载掩码设置
                    self.saved_mask = config.get('mask', '?a?a?a?a?a?a?a?a')
                    self.saved_charset1 = config.get('charset1', '')
                    self.saved_charset2 = config.get('charset2', '')
                    self.saved_charset3 = config.get('charset3', '')
                    self.saved_charset4 = config.get('charset4', '')
        except Exception as e:
            print(f"加载配置失败: {e}")
            # 设置默认值
            self.saved_mask = '?a?a?a?a?a?a?a?a'
            self.saved_charset1 = ''
            self.saved_charset2 = ''
            self.saved_charset3 = ''
            self.saved_charset4 = ''
    
    def save_config(self):
        """保存配置"""
        function_logger.debug("HashcatGUI.save_config called")
        self.john_path = self.john_path_edit.text()
        self.hashcat_path = self.hashcat_path_edit.text()
        
        # 验证路径
        john_valid = False
        hashcat_valid = False
        
        if self.john_path.strip():
            # 检查是否为john.exe文件路径
            if os.path.exists(self.john_path) and os.path.isfile(self.john_path):
                john_valid = True
            # 检查是否为包含john.exe的目录路径
            elif os.path.exists(self.john_path) and os.path.isdir(self.john_path):
                john_exe_path = os.path.join(self.john_path, Config.JOHN_EXE)
                if os.path.exists(john_exe_path):
                    john_valid = True
                else:
                    self.config_status_label.setText(f"✗ John目录中未找到{Config.JOHN_EXE}，配置未保存")
                    self.config_status_label.setStyleSheet("color: red;")
                    return
            else:
                self.config_status_label.setText("✗ John路径不存在，配置未保存")
                self.config_status_label.setStyleSheet("color: red;")
                return
        
        if self.hashcat_path.strip():
            # 检查是否为hashcat.exe文件路径
            if os.path.exists(self.hashcat_path) and os.path.isfile(self.hashcat_path):
                hashcat_valid = True
            # 检查是否为包含hashcat.exe的目录路径
            elif os.path.exists(self.hashcat_path) and os.path.isdir(self.hashcat_path):
                hashcat_exe_path = os.path.join(self.hashcat_path, Config.HASHCAT_EXE)
                if os.path.exists(hashcat_exe_path):
                    hashcat_valid = True
                else:
                    self.config_status_label.setText(f"✗ Hashcat目录中未找到{Config.HASHCAT_EXE}，配置未保存")
                    self.config_status_label.setStyleSheet("color: red;")
                    return
            else:
                self.config_status_label.setText("✗ Hashcat路径不存在，配置未保存")
                self.config_status_label.setStyleSheet("color: red;")
                return
        
        config = {
            'john_path': self.john_path,
            'hashcat_path': self.hashcat_path,
            'mask': self.mask_edit.text() if hasattr(self, 'mask_edit') else '?a?a?a?a?a?a?a?a',
            'charset1': self.charset1_edit.text() if hasattr(self, 'charset1_edit') else '',
            'charset2': self.charset2_edit.text() if hasattr(self, 'charset2_edit') else '',
            'charset3': self.charset3_edit.text() if hasattr(self, 'charset3_edit') else '',
            'charset4': self.charset4_edit.text() if hasattr(self, 'charset4_edit') else ''
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            # 显示保存成功和验证结果
            status_msg = "配置已保存"
            if john_valid and hashcat_valid:
                status_msg += " - 所有路径验证成功"
            elif john_valid or hashcat_valid:
                status_msg += " - 部分路径验证成功"
            
            self.config_status_label.setText(status_msg)
            self.config_status_label.setStyleSheet("color: green;")
            
        except Exception as e:
            self.config_status_label.setText(f"保存失败: {str(e)}")
            self.config_status_label.setStyleSheet("color: red;")
    
    def check_tools(self):
        function_logger.debug("HashcatGUI.check_tools called")
        """检查工具是否可用"""
        # 检查John the Ripper
        if os.path.exists(self.john_path):
            self.log_text.append("✓ John the Ripper 路径正确")
        else:
            self.log_text.append("✗ John the Ripper 路径不存在")
        
        # 检查Hashcat
        try:
            hashcat_exe_path = self.get_hashcat_exe_path()
            if not hashcat_exe_path:
                hashcat_path = self.hashcat_path_edit.text().strip()
                # 如果不是绝对路径，尝试在PATH中查找
                if not os.path.isabs(hashcat_path):
                    import shutil
                    hashcat_full_path = shutil.which(hashcat_path)
                    if hashcat_full_path:
                        self.log_text.append(f"✓ Hashcat 在系统PATH中找到: {hashcat_full_path}")
                        hashcat_exe_path = hashcat_path
                    else:
                        self.log_text.append("✗ Hashcat 未在系统PATH中找到，请设置完整路径")
                        return
                else:
                    self.log_text.append("✗ Hashcat 路径不存在或无效")
                    return
            
            # Windows下隐藏控制台窗口
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            result = subprocess.run([hashcat_exe_path, "--version"], 
                                  capture_output=True, text=True, timeout=5, encoding='utf-8',
                                  creationflags=creation_flags)
            if result.returncode == 0:
                self.log_text.append("✓ Hashcat 可用")
            else:
                self.log_text.append(f"✗ Hashcat 不可用，返回码: {result.returncode}")
        except FileNotFoundError:
            self.log_text.append("✗ Hashcat 文件未找到，请检查路径设置")
        except subprocess.TimeoutExpired:
            self.log_text.append("✗ Hashcat 检查超时")
        except Exception as e:
            self.log_text.append(f"✗ Hashcat 路径错误或不可用: {str(e)}")
    
    def get_hashcat_exe_path(self):
        """获取hashcat可执行文件路径（带缓存机制）"""
        function_logger.debug("HashcatGUI.get_hashcat_exe_path called")
        hashcat_path = self.hashcat_path_edit.text().strip()
        if not hashcat_path:
            return None
        
        # 检查缓存
        if hasattr(self, '_hashcat_path_cache'):
            cached_input, cached_result = self._hashcat_path_cache
            if cached_input == hashcat_path:
                return cached_result
        
        # 执行路径检查
        result = None
        
        # 检查是否为hashcat.exe文件路径
        if os.path.exists(hashcat_path) and os.path.isfile(hashcat_path):
            result = hashcat_path
        # 检查是否为包含hashcat.exe的目录路径
        elif os.path.exists(hashcat_path) and os.path.isdir(hashcat_path):
            potential_path = os.path.join(hashcat_path, Config.HASHCAT_EXE)
            if os.path.exists(potential_path):
                result = potential_path
        
        # 缓存结果
        self._hashcat_path_cache = (hashcat_path, result)
        return result
    
    def refresh_device_list(self):
        """刷新设备列表"""
        function_logger.debug("HashcatGUI.refresh_device_list called")
        # 清除现有的设备复选框
        for checkbox in self.device_checkboxes:
            checkbox.setParent(None)
            checkbox.deleteLater()
        self.device_checkboxes.clear()
        
        # 获取hashcat可执行文件路径
        hashcat_exe_path = self.get_hashcat_exe_path()
        if not hashcat_exe_path:
            error_label = QLabel("错误: 请先在路径配置中设置正确的Hashcat路径")
            error_label.setStyleSheet("color: red;")
            self.device_list_layout.addWidget(error_label)
            self.device_checkboxes.append(error_label)
            return
        
        try:
            # 确定工作目录为hashcat所在目录
            working_dir = os.path.dirname(hashcat_exe_path)
            
            # Windows下隐藏控制台窗口
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            result = subprocess.run([hashcat_exe_path, '-I'], 
                                  capture_output=True, text=True, 
                                  creationflags=creation_flags,
                                  cwd=working_dir,
                                  timeout=10)
            
            if result.returncode != 0:
                error_label = QLabel(f"获取设备信息失败: {result.stderr}")
                error_label.setStyleSheet("color: red;")
                self.device_list_layout.addWidget(error_label)
                self.device_checkboxes.append(error_label)
                return
            
            # 解析设备信息
            devices = self.parse_device_info(result.stdout)
            
            if not devices:
                no_device_label = QLabel("未找到可用设备")
                no_device_label.setStyleSheet("color: orange;")
                self.device_list_layout.addWidget(no_device_label)
                self.device_checkboxes.append(no_device_label)
                return
            
            # 创建设备复选框
            for device in devices:
                checkbox = QCheckBox(f"设备 #{device['id']}: {device['name']} ({device['type']})")
                checkbox.setChecked(True)  # 默认全选
                checkbox.stateChanged.connect(self.on_device_selection_changed)
                self.device_list_layout.addWidget(checkbox)
                self.device_checkboxes.append(checkbox)
                
        except subprocess.TimeoutExpired:
            error_label = QLabel("获取设备信息超时")
            error_label.setStyleSheet("color: red;")
            self.device_list_layout.addWidget(error_label)
            self.device_checkboxes.append(error_label)
        except FileNotFoundError as e:
            error_label = QLabel(f"找不到hashcat可执行文件: {hashcat_exe_path}")
            error_label.setStyleSheet("color: red;")
            self.device_list_layout.addWidget(error_label)
            self.device_checkboxes.append(error_label)
        except Exception as e:
            error_label = QLabel(f"获取设备信息时出错: {str(e)}")
            error_label.setStyleSheet("color: red;")
            self.device_list_layout.addWidget(error_label)
            self.device_checkboxes.append(error_label)
    
    def parse_device_info(self, output):
        """解析hashcat -I的输出，提取设备信息"""
        function_logger.debug("HashcatGUI.parse_device_info called")
        devices = []
        lines = output.split('\n')
        
        current_device = None
        for line in lines:
            line = line.strip()
            
            # 查找设备ID行
            if 'Backend Device ID #' in line or 'Device ID #' in line:
                if current_device and current_device.get('id') and current_device.get('name'):
                    devices.append(current_device)
                
                # 提取设备ID
                import re
                match = re.search(r'(?:Backend )?Device ID #(\d+)', line)
                if match:
                    current_device = {
                        'id': match.group(1),
                        'type': '',
                        'name': ''
                    }
            
            # 提取设备类型
            elif current_device and line.startswith('Type') and ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_device['type'] = parts[1].strip()
            
            # 提取设备名称
            elif current_device and line.startswith('Name') and ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    current_device['name'] = parts[1].strip()
        
        # 添加最后一个设备
        if current_device and current_device.get('id') and current_device.get('name'):
            devices.append(current_device)
        
        return devices
    
    def select_all_devices(self):
        """全选所有设备"""
        function_logger.debug("HashcatGUI.select_all_devices called")
        for checkbox in self.device_checkboxes:
            if isinstance(checkbox, QCheckBox):
                checkbox.setChecked(True)
    
    def deselect_all_devices(self):
        """全不选所有设备"""
        function_logger.debug("HashcatGUI.deselect_all_devices called")
        for checkbox in self.device_checkboxes:
            if isinstance(checkbox, QCheckBox):
                checkbox.setChecked(False)
    
    def on_device_selection_changed(self):
        """设备选择改变时的处理"""
        function_logger.debug("HashcatGUI.on_device_selection_changed called")
        self.update_command_preview()
    
    def get_selected_devices(self):
        """获取选中的设备ID列表"""
        function_logger.debug("HashcatGUI.get_selected_devices called")
        selected_devices = []
        for checkbox in self.device_checkboxes:
            if isinstance(checkbox, QCheckBox) and checkbox.isChecked():
                # 从复选框文本中提取设备ID
                text = checkbox.text()
                import re
                match = re.search(r'设备 #(\d+):', text)
                if match:
                    selected_devices.append(match.group(1))
        return selected_devices
    
    def _log_command_output(self, output: str, prefix: str) -> None:
        """记录命令输出到日志，统一处理输出长度限制
        
        Args:
            output: 命令输出内容
            prefix: 日志前缀
        """
        if not output:
            return
            
        output_stripped = output.strip()
        if not output_stripped:
            return
            
        # 统一的输出长度限制处理
        max_length = 1000
        if len(output_stripped) > max_length:
            truncated_output = f"{output_stripped[:500]}...[输出过长，已截断]...{output_stripped[-500:]}"
            self.log_text.append(f"{prefix}: {truncated_output}")
        else:
            self.log_text.append(f"{prefix}: {output_stripped}")
    
    def _on_hashcat_path_changed(self) -> None:
        """Hashcat路径改变时的处理"""
        # 清除路径缓存
        if hasattr(self, '_hashcat_path_cache'):
            delattr(self, '_hashcat_path_cache')
        
        # 执行原有的验证逻辑
        self.validate_hashcat_path(self.hashcat_path_edit.text())
    
    def get_hash_from_file(self, file_path: str, silent_cache: bool = False) -> Tuple[Optional[str], str]:
        function_logger.debug(f"HashcatGUI.get_hash_from_file called with file_path: {file_path}")
        """从文件提取哈希"""
        try:
            # 检查文件是否存在和可读
            if not os.path.exists(file_path):
                return None, "文件不存在"
            
            if not os.access(file_path, os.R_OK):
                return None, "文件无读取权限，请检查文件权限或关闭占用该文件的程序"
            
            # 检查缓存 - 避免重复调用xxx2john工具
            file_mtime = os.path.getmtime(file_path)
            if file_path in self.hash_cache:
                cached_hash, cached_type, cached_mtime = self.hash_cache[file_path]
                # 如果文件未被修改，直接返回缓存结果
                if cached_mtime == file_mtime:
                    # 只有在非静默模式下才输出缓存信息
                    if not silent_cache:
                        # 获取文件大小信息
                        try:
                            file_size = os.path.getsize(file_path)
                            size_str = f"{file_size:,} 字节" if file_size < 1024*1024 else f"{file_size/(1024*1024):.1f} MB"
                        except:
                            size_str = "未知大小"
                        
                        # 计算缓存时间
                        cache_time = datetime.datetime.fromtimestamp(cached_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        
                        self.log_text.append(f"✓ 使用缓存的哈希值")
                        self.log_text.append(f"  文件: {os.path.basename(file_path)}")
                        self.log_text.append(f"  类型: {cached_type}")
                        self.log_text.append(f"  大小: {size_str}")
                        self.log_text.append(f"  缓存时间: {cache_time}")
                        self.log_text.append(f"  哈希: {cached_hash[:32]}..." if len(cached_hash) > 32 else f"  哈希: {cached_hash}")
                    return cached_hash, cached_type
            
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # 获取正确的工具路径
            john_exe_path = None
            
            # 处理相对路径和绝对路径
            if not os.path.isabs(self.john_path):
                # 如果是相对路径，转换为绝对路径
                john_path_abs = os.path.abspath(self.john_path)
            else:
                john_path_abs = self.john_path
            
            # 检查是否为john.exe文件路径
            if os.path.exists(john_path_abs) and os.path.isfile(john_path_abs):
                john_exe_path = john_path_abs
            # 检查是否为包含john.exe的目录路径
            elif os.path.exists(john_path_abs) and os.path.isdir(john_path_abs):
                potential_john_path = os.path.join(john_path_abs, Config.JOHN_EXE)
                if os.path.exists(potential_john_path):
                    john_exe_path = potential_john_path
                else:
                    return None, f"John目录中未找到{Config.JOHN_EXE}"
            else:
                return None, f"John路径不存在: {john_path_abs}"
            
            if file_ext == '.zip':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ZIP2JOHN_EXE)
            elif file_ext == '.rar':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.RAR2JOHN_EXE)
            elif file_ext == '.7z':
                # 首先尝试查找可执行版本
                tool_path_exe = john_exe_path.replace(Config.JOHN_EXE, Config.SEVENZ2JOHN_EXE)
                tool_path_pl = john_exe_path.replace(Config.JOHN_EXE, Config.SEVENZ2JOHN_PL)
                if os.path.exists(tool_path_exe):
                    tool_path = tool_path_exe
                elif os.path.exists(tool_path_pl):
                    tool_path = tool_path_pl
                else:
                    return None, "未找到7z2john工具"
            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.OFFICE2JOHN_PY)
            elif file_ext == '.pdf':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.PDF2JOHN_PL)
            elif file_ext in ['.odt', '.ods', '.odp', '.odg', '.odf']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.LIBREOFFICE2JOHN_PY)
            elif file_ext in ['.sxc', '.sxw', '.sxi', '.sxd']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.STAROFFICE2JOHN_PY)
            # 密码管理器
            elif file_ext in ['.kdbx', '.kdb']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.KEEPASS2JOHN_EXE)
            elif file_ext == '.psafe3':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.PWSAFE2JOHN_PY)
            elif file_ext in ['.enpassdb', '.walletx']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ENPASS2JOHN_PY)
            elif file_ext == '.db':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.BITWARDEN2JOHN_PY)
            # 加密货币钱包
            elif file_ext in ['.dat', '.wallet']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.BITCOIN2JOHN_PY)
            elif file_ext in ['.json', '.keystore']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ETHEREUM2JOHN_PY)
            elif file_ext == '.multibit':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.MULTIBIT2JOHN_PY)
            elif file_ext == '.electrum':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ELECTRUM2JOHN_PY)
            # Apple相关
            elif file_ext in ['.key', '.numbers', '.pages']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.IWORK2JOHN_PY)
            elif file_ext == '.plist':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ITUNES_BACKUP2JOHN_PL)
            elif file_ext == '.keychain':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.KEYCHAIN2JOHN_PY)
            elif file_ext == '.dmg':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.DMG2JOHN_PY)
            # 磁盘加密
            elif file_ext in ['.tc', '.hc']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.TRUECRYPT2JOHN_PY)
            elif file_ext in ['.luks', '.img']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.LUKS2JOHN_PY)
            # 文件加密
            elif file_ext == '.axx':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.AXCRYPT2JOHN_PY)
            elif file_ext == '.encfs6.xml':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.ENCFS2JOHN_PY)
            # 应用程序
            elif file_ext in ['.id', '.nsf']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.LOTUS2JOHN_PY)
            elif file_ext in ['.key3.db', '.key4.db']:
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.MOZILLA2JOHN_PY)
            elif file_ext == '.xml':
                tool_path = john_exe_path.replace(Config.JOHN_EXE, Config.FILEZILLA2JOHN_PY)
            else:
                # 对于无扩展名文件，尝试检测VeraCrypt文件
                if not file_ext:
                    veracrypt_tool_path = self._detect_veracrypt_file(file_path)
                    if veracrypt_tool_path:
                        tool_path = veracrypt_tool_path
                    else:
                        return None, "无法识别文件类型。对于VeraCrypt文件，请确保文件是有效的VeraCrypt容器。"
                else:
                    # 尝试使用hashcat工具
                    hashcat_tool_path = self._get_hashcat_tool_path(file_ext, file_path)
                    if hashcat_tool_path:
                        tool_path = hashcat_tool_path
                    else:
                        return None, f"不支持的文件类型: {file_ext}。请查看支持的文件类型列表。"
            
            # 检查工具是否存在
            if not os.path.exists(tool_path):
                return None, f"工具不存在: {tool_path}"
            
            # 根据文件类型构建命令
            # 检查是否为hashcat工具
            hashcat_path = self.hashcat_path_edit.text().strip()
            if hashcat_path:
                if not os.path.isabs(hashcat_path):
                    hashcat_path_abs = os.path.abspath(hashcat_path)
                else:
                    hashcat_path_abs = hashcat_path
                    
                if os.path.isfile(hashcat_path_abs) and hashcat_path_abs.endswith('hashcat.exe'):
                    hashcat_dir = os.path.dirname(hashcat_path_abs)
                elif os.path.isdir(hashcat_path_abs):
                    hashcat_dir = hashcat_path_abs
                else:
                    hashcat_dir = None
                    
                is_hashcat_tool = hashcat_dir and tool_path.startswith(os.path.join(hashcat_dir, 'tools'))
            else:
                is_hashcat_tool = False
            
            python_script_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp', '.odg', '.odf',
                                       '.sxc', '.sxw', '.sxi', '.sxd', '.psafe3', '.enpassdb', '.walletx', '.db',
                                       '.dat', '.wallet', '.json', '.keystore', '.multibit', '.electrum',
                                       '.key', '.numbers', '.pages', '.keychain', '.dmg', '.tc', '.hc',
                                       '.luks', '.img', '.axx', '.encfs6.xml', '.id', '.nsf', '.key3.db', '.key4.db', '.xml']
            
            # hashcat工具的Python脚本
            hashcat_python_extensions = ['.loop', '.metamask', '.vc', '.vdi', '.vmx']
            
            perl_script_extensions = ['.pdf', '.plist']
            
            # hashcat工具的Perl脚本
            hashcat_perl_extensions = ['.aes', '.v2', '.notes']
            
            # 合并扩展名列表
            if is_hashcat_tool:
                python_script_extensions.extend(hashcat_python_extensions)
                perl_script_extensions.extend(hashcat_perl_extensions)
            
            if file_ext in python_script_extensions:
                # Python脚本 - 检查Python是否可用
                try:
                    # Windows下隐藏控制台窗口
                    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    subprocess.run(['python', '--version'], capture_output=True, check=True, creationflags=creation_flags)
                    # 为特定的hashcat工具添加必要的参数
                    if is_hashcat_tool:
                        if tool_path.endswith('vmwarevmx2hashcat.py'):
                            cmd = ['python', tool_path, '--vmx', file_path]
                        elif tool_path.endswith('virtualbox2hashcat.py'):
                            cmd = ['python', tool_path, '--vbox', file_path]
                        elif tool_path.endswith('metamask2hashcat.py'):
                            cmd = ['python', tool_path, '--vault', file_path]
                        elif tool_path.endswith('cryptoloop2hashcat.py'):
                            cmd = ['python', tool_path, '--source', file_path]
                        elif tool_path.endswith('bitwarden2hashcat.py'):
                            cmd = ['python', tool_path, file_path]
                        else:
                            # 大部分hashcat工具只需要文件路径作为位置参数
                            cmd = ['python', tool_path, file_path]
                    else:
                        cmd = ['python', tool_path, file_path]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    return None, f"Python未安装或不可用，无法处理{file_ext}文件"
            elif file_ext in perl_script_extensions or (file_ext == '.7z' and tool_path.endswith('.pl')):
                # Perl脚本 - 检查Perl是否可用
                try:
                    # Windows下隐藏控制台窗口
                    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    subprocess.run(['perl', '--version'], capture_output=True, check=True, creationflags=creation_flags)
                    # 为特定的hashcat工具添加必要的参数
                    if is_hashcat_tool:
                        if tool_path.endswith('aescrypt2hashcat.pl'):
                            cmd = ['perl', tool_path, '--aes', file_path]
                        elif tool_path.endswith('radmin3_to_hashcat.pl'):
                            cmd = ['perl', tool_path, '--radmin', file_path]
                        elif tool_path.endswith('securenotes2hashcat.pl'):
                            cmd = ['perl', tool_path, '--notes', file_path]
                        else:
                            cmd = ['perl', tool_path, file_path]
                    else:
                        cmd = ['perl', tool_path, file_path]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    if file_ext == '.pdf':
                        # PDF特殊处理：尝试Python版本
                        python_pdf_tool = john_exe_path.replace(Config.JOHN_EXE, Config.PDF2JOHN_PY)
                        if os.path.exists(python_pdf_tool):
                            try:
                                # Windows下隐藏控制台窗口
                                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                                subprocess.run(['python', '--version'], capture_output=True, check=True, creationflags=creation_flags)
                                cmd = ['python', python_pdf_tool, file_path]
                                tool_path = python_pdf_tool
                            except (subprocess.CalledProcessError, FileNotFoundError):
                                return None, "Python和Perl都不可用，无法处理PDF文件"
                        else:
                            return None, "Perl未安装且没有找到Python版本的PDF工具，无法处理PDF文件"
                    else:
                        return None, f"Perl未安装，无法处理{file_ext}文件。请安装Perl。"
            else:
                # 可执行文件
                cmd = [tool_path, file_path]
            
            # 记录执行的命令到日志
            self.log_text.append(f"执行哈希提取命令: {' '.join(cmd)}")
            
            # 使用绝对路径并设置工作目录，处理编码错误，设置10秒超时防止卡死
            # 在Windows系统中使用系统默认编码来正确处理中文文件名
            system_encoding = locale.getpreferredencoding()
            # Windows下隐藏控制台窗口
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, 
                                  encoding=system_encoding, errors='replace', cwd=os.path.dirname(tool_path),
                                  creationflags=creation_flags)
            
            # 记录命令执行结果到日志，限制输出长度防止超长内容
            if result.stdout:
                stdout_output = result.stdout.strip()
                if len(stdout_output) > 5000:  # 限制输出长度，但允许完整哈希值显示
                    self.log_text.append(f"工具输出: {stdout_output[:100]}...[输出超过5K，已截断]...{stdout_output[-100:]}")
                else:
                    self.log_text.append(f"工具输出: {stdout_output}")
            if result.stderr:
                stderr_output = result.stderr.strip()
                if len(stderr_output) > 1000:
                    self.log_text.append(f"工具错误输出: {stderr_output[:100]}...[输出过长，已截断]...{stderr_output[-100:]}")
                else:
                    self.log_text.append(f"工具错误输出: {stderr_output}")
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "未知错误"
                return None, f"提取哈希失败: {error_msg}"
            
            # 安全地处理 stdout，防止 None 值和超长输出
            output = result.stdout.strip() if result.stdout else ""
            if not output:
                return None, "未能提取到哈希值"
            
            # 检查输出长度，防止超长哈希值导致程序卡死
            if len(output) > 50000:  # 50KB限制
                return None, f"哈希输出过长({len(output)}字符)，可能文件损坏或格式异常"
            
            # 解析输出
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # 检查单行长度，防止超长哈希行
                if len(line) > 10000:  # 10KB单行限制
                    self.log_text.append(f"警告: 跳过超长哈希行({len(line)}字符)")
                    continue
                
                hash_value = None
                
                # 方式1: 直接是哈希值（如iTunes备份）
                if line.startswith('$'):
                    hash_value = line
                
                # 方式2: 包含冒号的格式
                elif ':' in line:
                    # 查找$符号位置
                    dollar_pos = line.find('$')
                    if dollar_pos != -1:
                        # 从$开始提取哈希部分
                        remaining = line[dollar_pos:]
                        
                        # 处理特殊的::::分隔符（如某些RAR格式）
                        if '::::' in remaining:
                            hash_value = remaining.split('::::')[0]
                            # 对于RAR3格式，检查并移除:0后缀
                            if hash_value.startswith('$RAR3$') and hash_value.endswith(':0'):
                                # RAR3格式: $RAR3$*type*salt*hash
                                # 如果salt为空(即*0*)，则移除:0后缀
                                if '*0*' in hash_value:
                                    hash_value = hash_value[:-2]
                        else:
                            # 标准格式，可能有多个冒号分隔的字段
                            # 找到哈希结束位置（通常是第一个非哈希字符或特定模式）
                            hash_value = remaining
                            
                            # 移除常见的后缀模式
                            # 对于RAR3格式，当salt为空时不应该有:0后缀
                            if hash_value.endswith(':0'):
                                # 检查是否为RAR3格式且salt为空的情况
                                if hash_value.startswith('$RAR3$'):
                                    # RAR3格式: $RAR3$*type*salt*hash
                                    # 如果salt为空(即*0*)，则移除:0后缀
                                    if '*0*' in hash_value:
                                        hash_value = hash_value[:-2]
                                else:
                                    # 对于其他格式，也移除:0后缀（保持原有逻辑）
                                    hash_value = hash_value[:-2]
                
                # 方式3: 保底处理 - 如果上述方法都没找到哈希，尝试其他模式
                if not hash_value and '$' in line:
                    # 简单提取：从第一个$到行尾
                    dollar_pos = line.find('$')
                    if dollar_pos != -1:
                        hash_value = line[dollar_pos:]
                        
                        # 清理常见的无关后缀
                        # 对于RAR3格式的特殊处理
                        if hash_value.startswith('$RAR3$') and hash_value.endswith(':0'):
                            # RAR3格式: $RAR3$*type*salt*hash
                            # 如果salt为空(即*0*)，则移除:0后缀
                            if '*0*' in hash_value:
                                hash_value = hash_value[:-2]
                        else:
                            # 对于其他格式，清理常见后缀
                            for suffix in [':0', '::::']:
                                if suffix in hash_value:
                                    hash_value = hash_value.split(suffix)[0]
                                    break
                
                # 如果成功提取到哈希值，进行验证和类型检测
                if hash_value and hash_value.startswith('$'):
                    # 最终检查哈希值长度
                    if len(hash_value) > 5000:  # 5KB哈希值限制
                        return None, f"提取的哈希值过长({len(hash_value)}字符)，可能文件异常"
                    
                    # 基本格式验证：确保哈希值看起来合理
                    if '$' in hash_value and len(hash_value) > 10:
                        hash_type = HashDetector.detect_hash_type_by_file_ext(file_ext, hash_value)
                        # 保存到缓存
                        self.hash_cache[file_path] = (hash_value, hash_type, file_mtime)
                        return hash_value, hash_type
            
            return None, "无法解析哈希值"
            
        except subprocess.TimeoutExpired:
            return None, "提取哈希超时"
        except PermissionError:
            return None, "权限不足，请以管理员身份运行或检查文件权限"
        except FileNotFoundError as e:
            return None, f"文件或工具未找到: {str(e)}"
        except Exception as e:
            return None, f"提取哈希时出错: {str(e)}"
    
    def clear_hash_cache(self, max_entries: int = 100) -> None:
        """清理哈希缓存
        
        Args:
            max_entries: 最大缓存条目数，超过时清理最旧的条目
        """
        function_logger.debug(f"HashcatGUI.clear_hash_cache called with max_entries: {max_entries}")
        try:
            # 清理不存在的文件的缓存条目
            invalid_paths = []
            for file_path in self.hash_cache:
                if not os.path.exists(file_path):
                    invalid_paths.append(file_path)
            
            for path in invalid_paths:
                del self.hash_cache[path]
                self.log_text.append(f"清理无效缓存条目: {path}")
            
            # 如果缓存条目过多，清理最旧的条目
            if len(self.hash_cache) > max_entries:
                # 按文件修改时间排序，保留最新的条目
                sorted_items = sorted(self.hash_cache.items(), 
                                     key=lambda x: x[1][2], reverse=True)
                
                # 保留最新的max_entries个条目
                self.hash_cache = dict(sorted_items[:max_entries])
                
                removed_count = len(sorted_items) - max_entries
                if removed_count > 0:
                    self.log_text.append(f"清理了{removed_count}个旧缓存条目")
                    
        except Exception as e:
            self.log_text.append(f"清理缓存时出错: {str(e)}")
    
    def _detect_veracrypt_file(self, file_path: str) -> Optional[str]:
        """检测无扩展名的VeraCrypt文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            VeraCrypt工具路径，如果不是VeraCrypt文件则返回None
        """
        try:
            # VeraCrypt文件头部特征检测
            with open(file_path, 'rb') as f:
                # 读取前512字节用于检测
                header = f.read(512)
                
                # VeraCrypt文件通常在偏移64字节处有特定的签名
                # 检查文件大小是否合理（至少1MB，通常更大）
                file_size = os.path.getsize(file_path)
                if file_size < 1024 * 1024:  # 小于1MB的文件不太可能是VeraCrypt容器
                    return None
                
                # 检查是否包含VeraCrypt的特征字节
                # VeraCrypt容器通常在特定位置有加密的头部信息
                # 由于是加密的，我们主要检查文件大小和结构
                
                # 检查文件大小是否为512的倍数（VeraCrypt容器的特征）
                if file_size % 512 != 0:
                    return None
                    
                # 获取hashcat工具路径
                hashcat_path = self.hashcat_path_edit.text().strip()
                if not hashcat_path:
                    return None
                    
                # 处理相对路径和绝对路径
                if not os.path.isabs(hashcat_path):
                    hashcat_path_abs = os.path.abspath(hashcat_path)
                else:
                    hashcat_path_abs = hashcat_path
                    
                # 如果是hashcat.exe文件路径，获取其目录
                if os.path.isfile(hashcat_path_abs) and hashcat_path_abs.endswith('hashcat.exe'):
                    hashcat_dir = os.path.dirname(hashcat_path_abs)
                elif os.path.isdir(hashcat_path_abs):
                    hashcat_dir = hashcat_path_abs
                else:
                    return None
                    
                # hashcat工具在tools子目录中
                tools_dir = os.path.join(hashcat_dir, 'tools')
                if not os.path.exists(tools_dir):
                    return None
                    
                # 返回VeraCrypt工具路径
                veracrypt_tool_path = os.path.join(tools_dir, Config.VERACRYPT2HASHCAT_PY)
                if os.path.exists(veracrypt_tool_path):
                    return veracrypt_tool_path
                else:
                    return None
                    
        except Exception as e:
            # 如果读取文件出错，返回None
            return None
    
    def _get_hashcat_tool_path(self, file_ext: str, file_path: str = None) -> Optional[str]:
        """获取hashcat工具路径
        
        Args:
            file_ext: 文件扩展名
            
        Returns:
            hashcat工具的完整路径，如果不支持则返回None
        """
        function_logger.debug(f"HashcatGUI._get_hashcat_tool_path called with file_ext: {file_ext}")
        
        # 获取hashcat路径
        hashcat_path = self.hashcat_path_edit.text().strip()
        if not hashcat_path:
            return None
            
        # 处理相对路径和绝对路径
        if not os.path.isabs(hashcat_path):
            hashcat_path_abs = os.path.abspath(hashcat_path)
        else:
            hashcat_path_abs = hashcat_path
            
        # 如果是hashcat.exe文件路径，获取其目录
        if os.path.isfile(hashcat_path_abs) and hashcat_path_abs.endswith('hashcat.exe'):
            hashcat_dir = os.path.dirname(hashcat_path_abs)
        elif os.path.isdir(hashcat_path_abs):
            hashcat_dir = hashcat_path_abs
        else:
            return None
            
        # hashcat工具在tools子目录中
        tools_dir = os.path.join(hashcat_dir, 'tools')
        if not os.path.exists(tools_dir):
            return None
            
        # 根据文件扩展名选择对应的hashcat工具
        # 注意：某些扩展名可能与john工具重叠，hashcat工具优先级较低
        tool_mapping = {
            '.aes': Config.AESCRYPT2HASHCAT_PL,
            # Bitwarden: 通过特定文件名识别
            '.loop': Config.CRYPTOLOOP2HASHCAT_PY,
            # Exodus: 特定文件名 seed.seco
            '.luks': Config.LUKS2HASHCAT_PY,
            '.metamask': Config.METAMASK2HASHCAT_PY,
            '.v2': Config.RADMIN3_TO_HASHCAT_PL,  # Radmin 3
            '.notes': Config.SECURENOTES2HASHCAT_PL,
            # SQLCipher: 需要特殊处理，避免与普通.db文件冲突
            '.tc': Config.TRUECRYPT2HASHCAT_PY,
            '.vc': Config.VERACRYPT2HASHCAT_PY,
            '.vdi': Config.VIRTUALBOX2HASHCAT_PY,  # VirtualBox磁盘镜像
            '.vmx': Config.VMWAREVMX2HASHCAT_PY,  # VMware配置文件
        }
        
        # 特殊文件名处理
        if file_path:
            filename = os.path.basename(file_path).lower()
            if filename == 'seed.seco':
                tool_name = Config.EXODUS2HASHCAT_PY
            elif filename.endswith('.json') and 'bitwarden' in filename:
                tool_name = Config.BITWARDEN2HASHCAT_PY
            elif filename.endswith('.key3.db') or filename.endswith('.key4.db'):
                tool_name = Config.MOZILLA2HASHCAT_PY
            else:
                tool_name = tool_mapping.get(file_ext)
        else:
            tool_name = tool_mapping.get(file_ext)
        
        if not tool_name:
            return None
            
        tool_path = os.path.join(tools_dir, tool_name)
        if os.path.exists(tool_path):
            return tool_path
        else:
            return None
    
    def _update_command_preview_with_hash(self, hash_value: str) -> None:
        """使用已提取的哈希值更新命令预览
        
        Args:
            hash_value: 已提取的哈希值
        """
        function_logger.debug(f"HashcatGUI._update_command_preview_with_hash called with hash_value: {hash_value[:50]}...")
        try:
            if not hash_value:
                return
            
            cmd = self._build_base_command()
            if not cmd:
                return
            
            self._add_command_options(cmd)
            cmd.append(hash_value)
            
            # 显示命令
            cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in cmd)
            self.cmd_text.setText(cmd_str)
            self.start_btn.setEnabled(True)
            
        except Exception as e:
            ErrorHandler.handle_error(e, "生成命令时出错")
            self.cmd_text.setText(f"生成命令时出错: {str(e)}")
            self.start_btn.setEnabled(False)
     
    def update_command_preview(self) -> None:
        """更新命令预览（带防抖机制）"""
        function_logger.debug("HashcatGUI.update_command_preview called")
        
        # 防抖机制：取消之前的定时器
        if hasattr(self, '_update_timer'):
            self._update_timer.stop()
        
        # 创建新的定时器，延迟100ms执行
        self._update_timer = QTimer()
        self._update_timer.setSingleShot(True)
        self._update_timer.timeout.connect(self._do_update_command_preview)
        self._update_timer.start(100)
    
    def _do_update_command_preview(self) -> None:
        """实际执行命令预览更新"""
        try:
            hash_to_crack = self._get_hash_input()
            if not hash_to_crack:
                return
            
            cmd = self._build_base_command()
            if not cmd:
                return
            
            self._add_command_options(cmd)
            cmd.append(hash_to_crack)
            self._add_attack_parameters(cmd)
            
            # 显示命令
            self.cmd_text.setText(' '.join(cmd))
            self.start_btn.setEnabled(True)
            
        except Exception as e:
            ErrorHandler.handle_error(e, "生成命令时出错")
            self.cmd_text.setText(f"生成命令时出错: {str(e)}")
            self.start_btn.setEnabled(False)
    
    def _get_hash_input(self, cached_hash_value: Optional[str] = None) -> Optional[str]:
        """获取哈希输入
        
        Args:
            cached_hash_value: 可选的缓存哈希值
        """
        function_logger.debug("HashcatGUI._get_hash_input called")
        if self.file_radio.isChecked():
            return self._handle_file_mode(cached_hash_value)
        elif self.text_radio.isChecked():
            return self._handle_text_mode()
        else:
            return self._handle_batch_mode()
    
    def _handle_file_mode(self, cached_hash_value: Optional[str] = None) -> Optional[str]:
        """处理文件模式
        
        Args:
            cached_hash_value: 可选的缓存哈希值，如果提供则不重新提取
        """
        function_logger.debug("HashcatGUI._handle_file_mode called")
        file_path = self.file_path_edit.text().strip()
        if not file_path:
            self.cmd_text.setText("请选择要破解的文件")
            return None
        
        # 如果提供了缓存的哈希值，直接使用
        if cached_hash_value:
            return cached_hash_value
        
        # 在命令预览更新时，不输出缓存信息以避免重复输出
        hash_value, hash_type_or_error = self.get_hash_from_file(file_path, silent_cache=True)
        if hash_value is None:
            self.cmd_text.setText(f"错误: {hash_type_or_error}")
            return None
        
        # 只有在首次检测或用户未手动选择时才自动设置哈希类型
        # 检查当前选择的哈希类型是否与检测到的类型匹配
        current_hash_type = self.hash_type_combo.currentText().split(' - ')[0]
        detected_hash_type = hash_type_or_error
        
        # 如果当前选择的类型与检测到的类型不匹配，且不是用户手动选择的，则自动设置
        if not current_hash_type.startswith(detected_hash_type):
            # 检查是否有用户手动选择的标记
            if not hasattr(self, '_user_selected_hash_type') or not self._user_selected_hash_type:
                for i in range(self.hash_type_combo.count()):
                    if self.hash_type_combo.itemText(i).startswith(hash_type_or_error):
                        self.hash_type_combo.setCurrentIndex(i)
                        break
        
        return hash_value
    
    def _handle_text_mode(self) -> Optional[str]:
        """处理文本模式"""
        function_logger.debug("HashcatGUI._handle_text_mode called")
        hash_to_crack = self.hash_edit.text().strip()
        if not hash_to_crack:
            self.cmd_text.setText("请输入哈希值")
            return None
        return hash_to_crack
    
    def _handle_batch_mode(self) -> Optional[str]:
        """处理批量模式"""
        function_logger.debug("HashcatGUI._handle_batch_mode called")
        batch_file = self.batch_path_edit.text().strip()
        if not batch_file:
            self.cmd_text.setText("请选择哈希列表文件")
            return None
        return batch_file
    
    def _build_base_command(self) -> Optional[List[str]]:
        """构建基础命令"""
        function_logger.debug("HashcatGUI._build_base_command called")
        hashcat_exe = self.get_hashcat_exe_path()
        if not hashcat_exe:
            self.cmd_text.setText("错误: 请先在路径配置中设置正确的Hashcat路径")
            self.start_btn.setEnabled(False)
            return None
        
        cmd = [hashcat_exe]
        attack_mode = self.attack_mode_combo.currentText().split(' - ')[0]
        cmd.extend(['-a', attack_mode])
        return cmd
    
    def _add_command_options(self, cmd: List[str]) -> None:
        """添加命令选项"""
        function_logger.debug("HashcatGUI._add_command_options called")
        # 哈希类型
        hash_type = self.hash_type_combo.currentText().split(' - ')[0]
        cmd.extend(['-m', hash_type])
        
        # 工作负载
        workload = self.workload_combo.currentText().split(' - ')[0]
        cmd.extend(['-w', workload])
        
        # 其他选项
        if self.show_potfile_check.isChecked():
            cmd.append('--show')
        if hasattr(self, 'quiet_check') and self.quiet_check.isChecked():
            cmd.append('--quiet')
        if hasattr(self, 'force_check') and self.force_check.isChecked():
            cmd.append('--force')
        
        # 设备选择
        self._add_device_options(cmd)
        
        # 输出文件
        if self.output_file_edit.text().strip():
            output_format = self.output_format_combo.currentText().split(' - ')[0]
            cmd.extend(['-o', self.output_file_edit.text().strip()])
            cmd.extend(['--outfile-format', output_format])
        
        # 自定义字符集
        self._add_custom_charsets(cmd)
        
        # 增量设置
        if not self.show_potfile_check.isChecked() and self.increment_check.isChecked():
            cmd.extend(['--increment'])
            cmd.extend(['--increment-min', self.min_len_edit.text()])
            cmd.extend(['--increment-max', self.max_len_edit.text()])
        
        # 性能调优选项
        self._add_performance_options(cmd)
        
        # 安全选项
        self._add_safety_options(cmd)
    
    def _add_device_options(self, cmd: List[str]) -> None:
        """添加设备选择选项"""
        function_logger.debug("HashcatGUI._add_device_options called")
        if hasattr(self, 'get_selected_devices'):
            selected_devices = self.get_selected_devices()
            manual_device_id = getattr(self, 'manual_device_edit', None)
            
            if manual_device_id and manual_device_id.text().strip():
                cmd.extend(["-d", manual_device_id.text().strip()])
            elif selected_devices:
                device_ids = ",".join(selected_devices)
                cmd.extend(["-d", device_ids])
    
    def _add_custom_charsets(self, cmd: List[str]) -> None:
        """添加自定义字符集"""
        function_logger.debug("HashcatGUI._add_custom_charsets called")
        charset_edits = [
            (self.charset1_edit, '-1'),
            (self.charset2_edit, '-2'),
            (self.charset3_edit, '-3'),
            (self.charset4_edit, '-4')
        ]
        
        for edit, flag in charset_edits:
            if edit.text().strip():
                cmd.extend([flag, edit.text().strip()])
    
    def _add_performance_options(self, cmd: List[str]) -> None:
        """添加性能调优选项"""
        function_logger.debug("HashcatGUI._add_performance_options called")
        if hasattr(self, 'kernel_loops_edit') and self.kernel_loops_edit.text().strip():
            cmd.extend(['-n', self.kernel_loops_edit.text().strip()])
        if hasattr(self, 'kernel_threads_edit') and self.kernel_threads_edit.text().strip():
            cmd.extend(['-u', self.kernel_threads_edit.text().strip()])
        if hasattr(self, 'optimized_kernel_check') and self.optimized_kernel_check.isChecked():
            cmd.append('-O')
    
    def _add_safety_options(self, cmd: List[str]) -> None:
        """添加安全选项"""
        function_logger.debug("HashcatGUI._add_safety_options called")
        if hasattr(self, 'temp_abort_edit') and self.temp_abort_edit.text().strip():
            cmd.extend(['--hwmon-temp-abort', self.temp_abort_edit.text().strip()])
        if hasattr(self, 'runtime_edit') and self.runtime_edit.text().strip():
            cmd.extend(['--runtime', self.runtime_edit.text().strip()])
        if hasattr(self, 'status_timer_edit') and self.status_timer_edit.text().strip():
            cmd.extend(['--status-timer', self.status_timer_edit.text().strip()])
        else:
            cmd.extend(['--status-timer', Config.DEFAULT_STATUS_TIMER])
    
    def _add_attack_parameters(self, cmd: List[str]) -> None:
        """添加攻击参数（字典或掩码）"""
        function_logger.debug("HashcatGUI._add_attack_parameters called")
        if self.show_potfile_check.isChecked():
            return
        
        attack_mode = self.attack_mode_combo.currentText().split(' - ')[0]
        
        # 需要字典的模式
        if attack_mode in AttackModes.DICTIONARY_MODES:
            dict_path = self.dict_path_edit.text().strip()
            if dict_path:
                cmd.append(dict_path)
        
        # 需要掩码的模式
        if attack_mode in AttackModes.MASK_MODES:
            mask = self.mask_edit.text().strip()
            if mask:
                mask_error = self.validate_mask(mask)
                if mask_error:
                    self.cmd_text.setText(f"掩码错误: {mask_error}")
                    self.start_btn.setEnabled(False)
                    return
                cmd.append(mask)
    
    def validate_mask(self, mask: str) -> Optional[str]:
        """验证掩码中的自定义字符集"""
        function_logger.debug(f"HashcatGUI.validate_mask called with mask: {mask}")
        used_charsets = self._extract_custom_charsets_from_mask(mask)
        missing_charsets = self._check_missing_charsets(used_charsets)
        
        if missing_charsets:
            used_display = ', '.join([f'?{c}' for c in used_charsets if f'-{c}' in missing_charsets])
            missing_display = ', '.join(missing_charsets)
            return f"掩码中使用了 {used_display}，但未定义对应的自定义字符集 {missing_display}"
        
        return None
    
    def _extract_custom_charsets_from_mask(self, mask: str) -> Set[str]:
        """从掩码中提取使用的自定义字符集"""
        function_logger.debug(f"HashcatGUI._extract_custom_charsets_from_mask called with mask: {mask}")
        used_charsets = set()
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                char_type = mask[i + 1]
                if char_type in '1234':
                    used_charsets.add(char_type)
                i += 2
            else:
                i += 1
        return used_charsets
    
    def _check_missing_charsets(self, used_charsets: Set[str]) -> List[str]:
        """检查缺失的自定义字符集"""
        function_logger.debug(f"HashcatGUI._check_missing_charsets called with used_charsets: {used_charsets}")
        charset_mapping = {
            '1': self.charset1_edit,
            '2': self.charset2_edit,
            '3': self.charset3_edit,
            '4': self.charset4_edit
        }
        
        missing_charsets = []
        for charset_num in used_charsets:
            edit = charset_mapping.get(charset_num)
            if edit and not edit.text().strip():
                missing_charsets.append(f'-{charset_num}')
        
        return missing_charsets
    
    def on_show_potfile_toggled(self, checked):
        """处理显示已破解密码选项的切换"""
        function_logger.debug(f"HashcatGUI.on_show_potfile_toggled called with checked: {checked}")
        if checked:
            # 显示已破解密码时，禁用增量和掩码相关控件
            self.increment_check.setChecked(False)
            self.increment_check.setEnabled(False)
            self.min_len_edit.setEnabled(False)
            self.max_len_edit.setEnabled(False)
            
            # 如果当前是掩码攻击模式，切换到字典攻击
            current_mode = self.attack_mode_combo.currentText()
            if "掩码" in current_mode and "字典" not in current_mode:
                self.attack_mode_combo.setCurrentText("0 - 字典攻击")
        else:
            # 取消显示已破解密码时，重新启用相关控件
            self.increment_check.setEnabled(True)
            self.min_len_edit.setEnabled(True)
            self.max_len_edit.setEnabled(True)
        
        # 更新命令预览
        self.update_command_preview()
    
    def start_crack(self):
        """开始破解"""
        function_logger.debug("HashcatGUI.start_crack called")
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "警告", "已有任务在运行中")
            return
        
        # 清空上次爆破的状态信息
        self.status_info = {
            'gpu_temp': '--',
            'gpu_util': '--', 
            'speed': '--',
            'progress': '--',
            'eta': '--',
            'elapsed': '--',
            'mask': '--'
        }
        # 设置爆破进行中标志
        self.is_cracking = True
        
        # 重置破解成功检测标志
        self.crack_success_detected = False
        self.update_status_bar()
        
        # 获取命令
        command_text = self.cmd_text.toPlainText().strip()
        if not command_text or command_text.startswith("错误") or command_text.startswith("请"):
            QMessageBox.warning(self, "警告", "请先配置正确的参数")
            return
        
        # 解析命令
        command = command_text.split()
        
        # 添加--status参数以启用自动状态更新
        if '--status' not in command:
            command.append('--status')
        
        # 添加--status-timer参数设置状态更新间隔
        if '--status-timer' not in ' '.join(command):
            command.extend(['--status-timer', '5'])
        
        # 确定工作目录和hashcat可执行文件路径
        hashcat_exe_path = self.get_hashcat_exe_path()
        if not hashcat_exe_path:
            hashcat_path = self.hashcat_path_edit.text().strip()
            if os.path.isabs(hashcat_path):
                QMessageBox.warning(self, "错误", "Hashcat路径不存在或无效")
                return
            else:
                # 相对路径，假设在PATH中
                hashcat_exe_path = hashcat_path
                working_dir = os.getcwd()
        else:
            # 确定工作目录
            if os.path.isfile(hashcat_exe_path):
                working_dir = os.path.dirname(hashcat_exe_path)
            else:
                hashcat_path = self.hashcat_path_edit.text().strip()
                working_dir = hashcat_path if os.path.isdir(hashcat_path) else os.getcwd()
        
        # 更新命令中的hashcat路径
        if command and len(command) > 0:
            command[0] = hashcat_exe_path
        
        # 清空日志
        self.log_text.clear()
        self.log_text.append(f"开始执行: {' '.join(command)}")
        if working_dir:
            self.log_text.append(f"工作目录: {working_dir}")
        
        # 创建并启动工作线程
        self.worker = HashcatWorker(command, working_dir)
        self.worker.output_signal.connect(self.on_output)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.success_signal.connect(self.on_crack_success)
        self.worker.start()
        
        # 更新界面状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        # Hashcat控制功能已移除
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 不确定进度
        self.statusBar().showMessage("正在破解...")
    
    def stop_crack(self):
        """停止破解"""
        function_logger.debug("HashcatGUI.stop_crack called")
        """停止破解"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log_text.append("\n用户停止了破解过程")
            self.statusBar().showMessage("正在停止...")
        
        # 重置爆破进行中标志
        self.is_cracking = False
        
        # 更新界面状态
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        # Hashcat控制功能已移除
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage("已停止")
    
    def on_output(self, text):
        """处理输出"""
        function_logger.debug(f"HashcatGUI.on_output called with text: {text[:100]}...")
        try:
            # 检测是否包含破解成功的hash:password格式
            import re
            
            # 首先检测是否是错误信息，避免误判
            error_indicators = [
                "Token length exception",
                "malformed",
                "No hashes loaded",
                "This error happens if",
                "wrong hash type",
                "not as expected"
            ]
            
            is_error = any(indicator in text for indicator in error_indicators)
            
            # 检测是否所有哈希都已在potfile中找到
            if "All hashes found as potfile" in text and "Use --show to display them" in text:
                self.log_text.append(text)
                self.log_text.append("检测到所有哈希已在potfile中，正在自动执行--show命令显示结果...")
                # 自动执行--show命令
                self.auto_show_potfile_results()
                return
            
            # 只有在不是错误信息的情况下才检测破解成功
            if not is_error:
                hash_password_pattern = r'([a-fA-F0-9]{32,}):(.+)'
                match = re.search(hash_password_pattern, text)
                
                if match:
                    # 找到hash:password格式，进一步验证这是真正的破解结果
                    hash_part = match.group(1)
                    password_part = match.group(2)
                    
                    # 额外验证：确保不包含错误关键词
                    if not any(keyword in password_part for keyword in ["exception", "error", "failed"]):
                        # 设置破解成功检测标志
                        self.crack_success_detected = True
                        
                        # 构建带格式的HTML文本
                        highlighted_text = text.replace(
                            f"{hash_part}:{password_part}",
                            f"{hash_part}:<span style='color: red; font-weight: 900; font-size: 14px;'>{password_part}</span>"
                        )
                        
                        # 使用HTML格式插入文本
                        cursor = self.log_text.textCursor()
                        cursor.movePosition(cursor.End)
                        cursor.insertHtml(highlighted_text + "<br>")
                        
                        # 发送成功信号到主线程显示消息框
                        if hasattr(self, 'worker') and self.worker:
                             self.worker.success_signal.emit(hash_part, password_part)
                        else:
                             # 备用方案：在日志中显示结果
                             self.log_text.append(f"破解成功！明文：{password_part}")
                        return
            
            # 普通文本直接添加
            self.log_text.append(text)
            
            # 自动滚动到底部
            cursor = self.log_text.textCursor()
            cursor.movePosition(cursor.End)
            self.log_text.setTextCursor(cursor)
            
            # 解析hashcat状态信息并更新实时监控
            self.parse_hashcat_status(text)
            
        except Exception as e:
            # 捕获所有异常，防止程序崩溃
            try:
                self.log_text.append(f"输出处理错误: {str(e)}")
                self.log_text.append(f"原始输出: {text}")
            except:
                print(f"严重错误 - 无法处理输出: {str(e)}")
                print(f"原始输出: {text}")
    
    def on_finished(self, return_code):
        """处理完成"""
        function_logger.debug(f"HashcatGUI.on_finished called with return_code: {return_code}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # 重置爆破进行中标志
        self.is_cracking = False
        
        # 根据hashcat状态码文档：
        # 0 = OK/cracked (命令正常执行，但不一定找到破解结果)
        # 1 = exhausted (穷尽所有可能性但未找到结果)
        # 2 = aborted (用户中止)
        # 其他负数 = 各种错误
        
        if return_code == 0:
            # 返回码0只表示命令正常执行，不一定意味着破解成功
            # 只有在实际检测到hash:password格式的输出时才算真正破解成功
            # 这里不再自动显示"破解完成"，而是根据实际输出内容判断
            if hasattr(self, 'crack_success_detected') and self.crack_success_detected:
                # 如果之前检测到了破解成功，显示破解完成
                cursor = self.log_text.textCursor()
                cursor.movePosition(cursor.End)
                cursor.insertHtml("<br><span style='color: red; font-weight: 900; font-size: 14px;'>破解完成!</span><br>")
                self.statusBar().showMessage("破解完成")
            else:
                # 命令正常结束但未检测到破解结果
                self.log_text.append("\n任务执行完成")
                self.statusBar().showMessage("任务完成")
        elif return_code == 1:
            self.log_text.append("\n已穷尽所有可能性，未找到匹配的密码")
            self.statusBar().showMessage("未找到密码")
        elif return_code == 2:
            self.log_text.append("\n任务被中止")
            self.statusBar().showMessage("任务中止")
        else:
            self.log_text.append(f"\n任务结束，返回码: {return_code}")
            self.statusBar().showMessage("任务结束")
        
        # 重置破解成功检测标志
        self.crack_success_detected = False
        self.worker = None
    
    def on_crack_success(self, hash_part, password_part):
        """处理破解成功"""
        function_logger.debug(f"HashcatGUI.on_crack_success called with hash_part: {hash_part[:20]}..., password_part: {password_part}")
        """处理破解成功信号，在状态栏显示破解结果"""
        try:
            # 在状态栏显示破解成功信息
            self.statusBar().showMessage(f"🎉 破解成功！明文：{password_part}", 10000)  # 显示10秒
            # 同时在日志中记录
            self.log_text.append(f"破解成功！明文：{password_part}")
        except Exception as e:
            # 如果出错，至少在日志中显示结果
            self.log_text.append(f"破解成功！明文：{password_part}")
            print(f"状态栏显示错误: {str(e)}")
    
    def parse_hashcat_status(self, text):
        """解析hashcat状态信息并更新状态栏"""
        function_logger.debug(f"HashcatGUI.parse_hashcat_status called with text: {text[:100]}...")
        try:
            import re
            
            # 初始化状态信息
            if not hasattr(self, 'status_info'):
                self.status_info = {
                    'gpu_temp': '--',
                    'gpu_util': '--', 
                    'speed': '--',
                    'progress': '--',
                    'eta': '--',
                    'elapsed': '--',
                    'mask': '--'
                }
            
            # 解析速度信息 (例如: Speed.#1.........:   123.4 MH/s 或 Speed.#*.........: 24225.2 MH/s)
            if "Speed.#" in text and "H/s" in text:
                # 提取速度值，优先使用总速度（Speed.#*）
                total_speed_match = re.search(r'Speed\.#\*.*?:\s*([\d.,]+\s*[KMGT]?H/s)', text)
                if total_speed_match:
                    self.status_info['speed'] = total_speed_match.group(1)
                # 如果没有总速度，则使用单个设备的速度
                elif "Speed.#" in text:
                    speed_match = re.search(r'Speed\.#\d+.*?:\s*([\d.,]+\s*[KMGT]?H/s)', text)
                    if speed_match:
                        self.status_info['speed'] = speed_match.group(1)
            
            # 解析进度信息 (例如: Progress.........: 1292114067456/6634204312890625 (0.02%))
            if "Progress" in text and "%" in text:
                progress_match = re.search(r'Progress.*?\((\d+\.\d+)%\)', text)
                if progress_match:
                    self.status_info['progress'] = progress_match.group(1)
            
            # 解析预计完成时间 (例如: Time.Estimated...: Mon Jun 16 10:01:32 2025)
            if "Time.Estimated" in text:
                eta_match = re.search(r'Time\.Estimated.*?:\s*(.+)', text)
                if eta_match:
                    eta_text = eta_match.group(1).strip()
                    # 转换为中文格式
                    self.status_info['eta'] = self.format_eta_chinese(eta_text)
            
            # 解析开始时间和运行时长 (例如: Time.Started.....: Wed Oct 16 16:48:22 2024 (0 secs))
            if "Time.Started" in text:
                started_match = re.search(r'Time\.Started.*?:\s*(.+)', text)
                if started_match:
                    started_text = started_match.group(1).strip()
                    # 提取括号内的运行时长
                    elapsed_match = re.search(r'\(([^)]+)\)', started_text)
                    if elapsed_match:
                        elapsed_text = elapsed_match.group(1)
                        # 转换为中文格式
                        self.status_info['elapsed'] = self.format_elapsed_chinese(elapsed_text)
            
            # 解析当前掩码信息 (例如: Guess.Mask.......: ?a [1])
            if "Guess.Mask" in text:
                mask_match = re.search(r'Guess\.Mask.*?:\s*(.+)', text)
                if mask_match:
                    mask_text = mask_match.group(1).strip()
                    # 保留完整的掩码信息，包括数字标识
                    self.status_info['mask'] = mask_text
            
            # 解析GPU硬件监控信息 (例如: Hardware.Mon.#1..: Temp: 85c Util:100%)
            if "Hardware.Mon.#" in text:
                # 解析温度
                temp_match = re.search(r'Temp:\s*(\d+)c', text)
                if temp_match:
                    self.status_info['gpu_temp'] = temp_match.group(1)
                
                # 解析使用率
                util_match = re.search(r'Util:\s*(\d+)%', text)
                if util_match:
                    self.status_info['gpu_util'] = util_match.group(1)
            
            # 更新状态栏显示
            self.update_status_bar()
                    
        except Exception as e:
            # 静默处理解析错误，不影响主要功能
            pass
    
    def format_eta_chinese(self, eta_text):
        """将预计完成时间转换为中文格式"""
        function_logger.debug(f"HashcatGUI.format_eta_chinese called with eta_text: {eta_text}")
        try:
            import datetime
            import re
            
            # 检查是否包含括号内的剩余时间信息 (例如: Mon Jun 16 07:37:34 2025 (3 days, 7 hours))
            bracket_match = re.search(r'\(([^)]+)\)', eta_text)
            if bracket_match:
                remaining_text = bracket_match.group(1)
                # 解析剩余时间
                days_match = re.search(r'(\d+)\s+days?', remaining_text)
                hours_match = re.search(r'(\d+)\s+hours?', remaining_text)
                minutes_match = re.search(r'(\d+)\s+(minutes?|mins?)', remaining_text)
                seconds_match = re.search(r'(\d+)\s+(seconds?|secs?)', remaining_text)
                
                days = int(days_match.group(1)) if days_match else 0
                hours = int(hours_match.group(1)) if hours_match else 0
                minutes = int(minutes_match.group(1)) if minutes_match else 0
                seconds = int(seconds_match.group(1)) if seconds_match else 0
                
                if days > 0:
                    if minutes == 0 and seconds == 0:
                        return f"{days}天{hours}时"
                    else:
                        return f"{days}天{hours}时{minutes}分{seconds}秒"
                elif hours > 0:
                    if minutes == 0 and seconds == 0:
                        return f"{hours}时"
                    else:
                        return f"{hours}时{minutes}分{seconds}秒"
                elif minutes > 0:
                    if seconds == 0:
                        return f"{minutes}分"
                    else:
                        return f"{minutes}分{seconds}秒"
                else:
                    return f"{seconds}秒"
            
            # 如果是纯时间戳格式，计算剩余时间
            elif re.match(r'\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4}', eta_text):
                # 解析时间字符串
                from datetime import datetime
                eta_time = datetime.strptime(eta_text, '%a %b %d %H:%M:%S %Y')
                now = datetime.now()
                
                if eta_time > now:
                    delta = eta_time - now
                    days = delta.days
                    hours, remainder = divmod(delta.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    
                    if days > 0:
                        if minutes == 0 and seconds == 0:
                            return f"{days}天{hours}时"
                        else:
                            return f"{days}天{hours}时{minutes}分{seconds}秒"
                    elif hours > 0:
                        if minutes == 0 and seconds == 0:
                            return f"{hours}时"
                        else:
                            return f"{hours}时{minutes}分{seconds}秒"
                    elif minutes > 0:
                        if seconds == 0:
                            return f"{minutes}分"
                        else:
                            return f"{minutes}分{seconds}秒"
                    else:
                        return f"{seconds}秒"
                else:
                    return "即将完成"
            else:
                return eta_text
        except:
            return eta_text
    
    def format_elapsed_chinese(self, elapsed_text):
        """将运行时长转换为中文格式"""
        function_logger.debug(f"HashcatGUI.format_elapsed_chinese called with elapsed_text: {elapsed_text}")
        try:
            import re
            
            # 解析不同格式的时间
            # 处理 "0 secs", "5 mins, 30 secs", "2 hours, 15 mins", "1 day, 3 hours" 等格式
            days_match = re.search(r'(\d+)\s+days?', elapsed_text)
            hours_match = re.search(r'(\d+)\s+hours?', elapsed_text)
            minutes_match = re.search(r'(\d+)\s+mins?', elapsed_text)
            seconds_match = re.search(r'(\d+)\s+secs?', elapsed_text)
            
            days = int(days_match.group(1)) if days_match else 0
            hours = int(hours_match.group(1)) if hours_match else 0
            minutes = int(minutes_match.group(1)) if minutes_match else 0
            seconds = int(seconds_match.group(1)) if seconds_match else 0
            
            if days > 0:
                if minutes == 0 and seconds == 0:
                    return f"{days}天{hours}时"
                else:
                    return f"{days}天{hours}时{minutes}分{seconds}秒"
            elif hours > 0:
                if minutes == 0 and seconds == 0:
                    return f"{hours}时"
                else:
                    return f"{hours}时{minutes}分{seconds}秒"
            elif minutes > 0:
                if seconds == 0:
                    return f"{minutes}分"
                else:
                    return f"{minutes}分{seconds}秒"
            else:
                return f"{seconds}秒"
        except:
            return elapsed_text
    
    def update_status_bar(self):
        """更新状态栏显示（带状态缓存优化）"""
        function_logger.debug("HashcatGUI.update_status_bar called")
        try:
            # 检查是否有实际的监控数据
            has_data = any(value != '--' for value in self.status_info.values())
            
            if has_data:
                # 有数据时显示完整的监控信息
                elapsed_part = f" 已运行{self.status_info['elapsed']}" if self.status_info['elapsed'] != '--' else ""
                mask_part = f"掩码：{self.status_info['mask']} " if self.status_info['mask'] != '--' else ""
                status_text = f"GPU：{self.status_info['gpu_temp']}℃ {self.status_info['gpu_util']}% 速度：{self.status_info['speed']} {mask_part}进度 {self.status_info['progress']}%{elapsed_part} 预计{self.status_info['eta']}后完成"
            else:
                # 检查是否正在爆破中
                if hasattr(self, 'is_cracking') and self.is_cracking:
                    status_text = "正在破解..."
                else:
                    # 没有数据且不在爆破中时显示就绪状态
                    status_text = "就绪"
            
            # 状态缓存优化：只在状态文本变化时才更新UI
            if not hasattr(self, '_last_status_text') or self._last_status_text != status_text:
                self.statusBar().showMessage(status_text)
                self._last_status_text = status_text
                
        except:
            # 异常情况下，如果正在爆破则显示正在破解，否则显示就绪
            fallback_text = "正在破解..." if (hasattr(self, 'is_cracking') and self.is_cracking) else "就绪"
            if not hasattr(self, '_last_status_text') or self._last_status_text != fallback_text:
                self.statusBar().showMessage(fallback_text)
                self._last_status_text = fallback_text
    
    def auto_show_potfile_results(self):
        """自动执行--show命令显示potfile中的结果"""
        function_logger.debug("HashcatGUI.auto_show_potfile_results called")
        try:
            import subprocess
            import os
            
            # 获取hashcat可执行文件路径
            hashcat_exe_path = self.get_hashcat_exe_path()
            if not hashcat_exe_path:
                self.log_text.append("错误：无法找到hashcat可执行文件")
                return
            
            # 获取哈希输入
            hash_input = self._get_hash_input()
            if not hash_input:
                self.log_text.append("错误：无法获取哈希输入")
                return
            
            # 构建--show命令
            show_cmd = [hashcat_exe_path, "--show"]
            
            # 添加哈希类型参数
            hash_type = self.hash_type_combo.currentText().split(" - ")[0]
            show_cmd.extend(["-m", hash_type])
            
            # 添加哈希输入
            if self.file_radio.isChecked():
                # 文件模式：使用临时哈希文件
                temp_hash_file = os.path.join(os.path.dirname(hashcat_exe_path), "temp_hash.txt")
                with open(temp_hash_file, 'w', encoding='utf-8') as f:
                    f.write(hash_input)
                show_cmd.append(temp_hash_file)
            else:
                # 文本模式：直接使用哈希值
                show_cmd.append(hash_input)
            
            # 设置工作目录
            work_dir = os.path.dirname(hashcat_exe_path)
            
            # 执行--show命令
            self.log_text.append(f"执行命令: {' '.join(show_cmd)}")
            # 使用系统默认编码来正确处理中文文件名和输出
            system_encoding = locale.getpreferredencoding()
            # Windows下隐藏控制台窗口
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            result = subprocess.run(show_cmd, cwd=work_dir, capture_output=True, text=True, 
                                  timeout=30, encoding=system_encoding, errors='replace',
                                  creationflags=creation_flags)
            
            if result.returncode == 0 and result.stdout.strip():
                # 成功获取到结果
                self.log_text.append("\n=== Potfile中的破解结果 ===")
                
                # 处理输出，高亮显示密码部分
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ':' in line:
                        # 使用现有的输出处理逻辑来高亮显示
                        self.on_output(line)
                    else:
                        self.log_text.append(line)
                
                self.log_text.append("=== 结果显示完毕 ===")
            else:
                self.log_text.append("未找到已破解的结果或命令执行失败")
                if result.stderr:
                    self.log_text.append(f"错误信息: {result.stderr}")
            
            # 清理临时文件
            if self.file_radio.isChecked():
                try:
                    if os.path.exists(temp_hash_file):
                        os.remove(temp_hash_file)
                except:
                    pass
                    
        except subprocess.TimeoutExpired:
            self.log_text.append("--show命令执行超时")
        except Exception as e:
            self.log_text.append(f"执行--show命令时发生错误: {str(e)}")
    
    def on_mask_template_changed(self, template_text):
        """处理掩码模板选择变化"""
        function_logger.debug(f"HashcatGUI.on_mask_template_changed called with template_text: {template_text}")
        if template_text == "自定义":
            return
        
        # 提取模板中的掩码部分
        if " (" in template_text:
            mask = template_text.split(" (")[0]
            self.mask_edit.setText(mask)
            # 重置模板选择为自定义
            self.mask_template_combo.setCurrentText("自定义")
    
    def calculate_main_candidates(self):
        """计算主界面掩码的候选数量"""
        function_logger.debug("HashcatGUI.calculate_main_candidates called")
        mask = self.mask_edit.text().strip()
        if not mask:
            self.main_candidates_label.setText("预计候选数量: 无掩码")
            self.main_candidates_label.setStyleSheet("color: gray; font-weight: bold; font-size: 12px;")
            return
        
        try:
            total = 1
            i = 0
            while i < len(mask):
                if mask[i] == '?' and i + 1 < len(mask):
                    char_type = mask[i + 1]
                    if char_type == 'l':  # 小写字母
                        total *= 26
                    elif char_type == 'u':  # 大写字母
                        total *= 26
                    elif char_type == 'd':  # 数字
                        total *= 10
                    elif char_type == 's':  # 符号
                        total *= 33  # 常见符号数量
                    elif char_type == 'a':  # 所有字符
                        total *= 95  # 可打印ASCII字符
                    elif char_type in '1234':  # 自定义字符集
                        # 根据实际的自定义字符集长度计算
                        if char_type == '1' and self.charset1_edit.text().strip():
                            total *= len(self.charset1_edit.text().strip())
                        elif char_type == '2' and self.charset2_edit.text().strip():
                            total *= len(self.charset2_edit.text().strip())
                        elif char_type == '3' and self.charset3_edit.text().strip():
                            total *= len(self.charset3_edit.text().strip())
                        elif char_type == '4' and self.charset4_edit.text().strip():
                            total *= len(self.charset4_edit.text().strip())
                        else:
                            total *= 10  # 默认值
                    i += 2
                else:
                    i += 1
            
            if total > 1e12:
                self.main_candidates_label.setText(f"预计候选数量: {total:.2e} (非常大!)")
                self.main_candidates_label.setStyleSheet("color: red; font-weight: bold; font-size: 12px;")
            elif total > 1e9:
                self.main_candidates_label.setText(f"预计候选数量: {total:.2e} (很大)")
                self.main_candidates_label.setStyleSheet("color: orange; font-weight: bold; font-size: 12px;")
            else:
                self.main_candidates_label.setText(f"预计候选数量: {total:,}")
                self.main_candidates_label.setStyleSheet("color: blue; font-weight: bold; font-size: 12px;")
        except Exception as e:
            function_logger.error(f"计算候选数量时出错: {e}")
            self.main_candidates_label.setText("预计候选数量: 计算错误")
            self.main_candidates_label.setStyleSheet("color: red; font-weight: bold; font-size: 12px;")
    
    def browse_batch_file(self):
        """浏览批量哈希文件"""
        function_logger.debug("HashcatGUI.browse_batch_file called")
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择哈希列表文件", "", 
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_path:
            self.batch_path_edit.setText(file_path)
            self.update_command_preview()
    
    def load_help_content(self):
        """加载帮助文档内容"""
        function_logger.debug("HashcatGUI.load_help_content called")
        try:
            # 尝试读取hashcat.md文件
            help_file_path = os.path.join(os.path.dirname(__file__), "hashcat.md")
            if os.path.exists(help_file_path):
                with open(help_file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.help_text.setPlainText(content)
            else:
                # 如果文件不存在，显示基本帮助信息
                basic_help = """
# Hashcat GUI 帮助文档

## 基本使用

### 解密类型
- **文件解密**: 选择要破解的加密文件
- **文本解密**: 直接输入哈希值进行破解
- **批量解密**: 选择包含多个哈希值的文本文件

### 攻击模式
- **0 - 字典攻击**: 使用字典文件进行攻击
- **1 - 组合攻击**: 组合两个字典文件
- **3 - 掩码攻击**: 使用掩码模式生成密码
- **6 - 混合字典+掩码**: 字典后追加掩码
- **7 - 混合掩码+字典**: 掩码后追加字典
- **9 - 关联攻击**: 关联攻击模式

### 掩码字符
- ?l = 小写字母 (a-z)
- ?u = 大写字母 (A-Z)
- ?d = 数字 (0-9)
- ?s = 特殊符号
- ?a = 所有字符
- ?1-?4 = 自定义字符集

### 性能优化
- 调整工作负载等级
- 设置内核循环数和线程数
- 启用优化内核(-O)

### 安全设置
- 设置GPU温度限制
- 设置运行时间限制
- 调整状态更新间隔

## 常用哈希类型

### 系统密码
- 0: MD5
- 100: SHA1
- 1000: NTLM (Windows)
- 1800: sha512crypt (Linux)
- 500: md5crypt (Unix)

### 文档格式
- 9400-9600: MS Office
- 10400-10700: PDF
- 11600: 7-Zip
- 12500: RAR3
- 13000: RAR5

### 网络协议
- 2500: WPA-EAPOL-PBKDF2
- 16800: WPA-PMKID-PBKDF2
- 22000: WPA-PBKDF2-PMKID+EAPOL

更多详细信息请参考 hashcat 官方文档。
"""
                self.help_text.setPlainText(basic_help)
        except Exception as e:
            self.help_text.setPlainText(f"加载帮助文档时出错: {str(e)}")
    
    def update_performance_settings_in_command(self):
        """更新命令中的性能设置"""
        function_logger.debug("HashcatGUI.update_performance_settings_in_command called")
        # 这个方法会在update_command_preview中被调用
        # 用于添加新的性能和安全参数到命令中
        pass
    
    def closeEvent(self, event):
        """程序关闭事件处理"""
        function_logger.debug("HashcatGUI.closeEvent called")
        try:
            # 如果有正在运行的hashcat进程，先停止它
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                # 等待进程结束，最多等待3秒
                if not self.worker.wait(3000):
                    # 如果3秒后还没结束，强制终止
                    if self.worker.process:
                        self.worker.process.kill()
                        self.worker.wait(1000)  # 再等待1秒
            
            # 接受关闭事件
            event.accept()
        except Exception as e:
            print(f"关闭程序时出错: {str(e)}")
            # 即使出错也要关闭程序
            event.accept()

def main():
    function_logger.debug("main function called")
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 使用现代风格
    
    # 设置应用图标和样式
    app.setApplicationName("Hashcat GUI")
    app.setApplicationVersion("2.0")
    
    window = HashcatGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
