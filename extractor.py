import os
from pyexpat import features
import re
import math
import hashlib
import numpy as np
from collections import Counter
from typing import Dict, Optional
from functools import cache, lru_cache

class WebshellFeatureExtractor:
    VERSION = "8.0-aspx_enhanced+fp_reduction+framework_sigs"
    
    # ============ CORE PATTERNS (ENHANCED) ============
    # Fixed: Allow comment-splitting, stricter matching
    EXEC_PATTERN = re.compile(
        r'(?<!<%[#=]\s)'  # Negative lookbehind: not after <%# or <%=
        r'\b(eval|exec|system|shell_exec|passthru|popen|proc_open|assert|create_function|pcntl_exec)\b'
        r'\s*(?:/\*[\s\S]{0,80}?\*/\s*)*\(',
        re.I
    )
    
    # ASPX: Exclude databinding Eval
    ASPX_DATABINDING_EVAL = re.compile(r'<%[#=]\s*Eval\s*\(', re.I)
    ASPX_CODE_EVAL = re.compile(r'\beval\s*\((?!.*?<%)', re.I)
    
    DECODE_PATTERN = re.compile(
        r'\b(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|rawurldecode|convert_uudecode)\b\s*(?:/\*[\s\S]{0,80}?\*/\s*)*\(',
        re.I
    )
    
    DYNAMIC_EXEC_PATTERN = re.compile(
        r'\b(call_user_func|call_user_func_array|array_map|array_walk|register_shutdown_function|preg_replace)\b\s*(?:/\*[\s\S]{0,80}?\*/\s*)*\(',
        re.I
    )
    
    INPUT_PATTERN = re.compile(
        r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b'
        r'|\$(HTTP_GET_VARS|HTTP_POST_VARS|HTTP_COOKIE_VARS|HTTP_SERVER_VARS|HTTP_POST_FILES)\b'
        r'|filter_input\s*\(|filter_var\s*\('
        # FIXED: Allow comments between Request and accessor
        r'|Request\s*(?:/\*[\s\S]{0,50}?\*/\s*)*\.\s*(?:/\*[\s\S]{0,50}?\*/\s*)*(Form|QueryString|Params|Cookies)\s*(?:/\*[\s\S]{0,50}?\*/\s*)*\['
        # NEW: Support Request["key"] and Request.Item["key"]
        r'|Request\s*(?:/\*[\s\S]{0,50}?\*/\s*)*\['
        r'|Request\s*(?:/\*[\s\S]{0,50}?\*/\s*)*\.\s*(?:/\*[\s\S]{0,50}?\*/\s*)*Item\s*(?:/\*[\s\S]{0,50}?\*/\s*)*\[',
        re.I
    )
    
    # ============ ASPX ENHANCED PATTERNS ============
    # File Manager Operations
    ASPX_FILE_WRITE = re.compile(
        r'\b(File\.WriteAllText|File\.WriteAllBytes|File\.AppendAllText|StreamWriter|FileStream\.Write|'
        r'File\.Copy|File\.Move|File\.Delete|Directory\.CreateDirectory|Directory\.Delete)\b',
        re.I
    )
    
    ASPX_FILE_UPLOAD = re.compile(
        r'\b(Request\.Files|HttpPostedFile|PostedFile\.SaveAs|InputStream\.CopyTo)\b',
        re.I
    )
    
    ASPX_FILE_MANAGER = re.compile(
        r'(File\.WriteAllText|SaveAs|File\.Delete|Directory\.GetFiles|Directory\.GetDirectories)'
        r'[\s\S]{0,500}(Request\.(Form|QueryString|Params)|HttpPostedFile)',
        re.I | re.DOTALL
    )
    
    # Tunneling/Proxy Patterns (Tunna-style)
    ASPX_TUNNELING = re.compile(
        r'\b(HttpWebRequest|WebClient|TcpClient|Socket\.Connect|NetworkStream)\b'
        r'[\s\S]{0,800}(Request\.(Form|QueryString)|Session\[|base64|chunked)',
        re.I | re.DOTALL
    )
    
    ASPX_PROXY_KEYWORDS = re.compile(
        r'\b(tunnel|proxy|forward|relay|redirect|upstream)\b',
        re.I
    )
    
    # WinAPI/Privilege Escalation (InsomniaShell-style)
    ASPX_WINAPI_IMPORT = re.compile(
        r'DllImport\s*\(\s*["\']+(kernel32|advapi32|user32|ntdll)',
        re.I
    )
    
    ASPX_NAMED_PIPE = re.compile(
        r'\b(CreateNamedPipe|ConnectNamedPipe|CreateFile.*?PIPE|NamedPipeClientStream)\b',
        re.I
    )
    
    ASPX_PRIVILEGE_ESCALATION = re.compile(
        r'\b(ImpersonateNamedPipeClient|OpenProcessToken|DuplicateTokenEx|'
        r'AdjustTokenPrivileges|CreateProcessAsUser|LogonUser)\b',
        re.I
    )
    
    # Process Execution (existing, kept)
    ASPX_EXEC_PATTERN = re.compile(
        r'\b(Process\.Start|ProcessStartInfo|cmd\.exe|powershell|WScript\.Shell|eval\s*\()',
        re.I
    )
    
    ASPX_PROCESS_PIPE = re.compile(
        r'(RedirectStandardInput|RedirectStandardOutput|RedirectStandardError|'
        r'StandardInput\.Write(Line)?|UseShellExecute\s*=\s*false)',
        re.I
    )
    
    ASPX_REQUEST_INPUT = re.compile(r'Request\.(QueryString|Form|Params|Cookies)\s*\[', re.I)

    JSP_COMPILED_CLASS = re.compile(
        r'(?:extends\s+HttpJspBase|implements\s+JspSourceDependent)',
        re.I
    )

    # Pattern 2: Hardcoded suspicious command in String variable
    JSP_HARDCODED_COMMAND = re.compile(
        r'String\s+command\s*=\s*"[^"]*(?:curl|wget|ls\s+/|dir\s+[A-Z]:|nc\s+|bash|sh|cmd\.exe|powershell)[^"]*"',
        re.I
    )

    # Pattern 3: Runtime.exec(command) - variable-based execution
    JSP_RUNTIME_EXEC_COMMAND = re.compile(
        r'Runtime\.getRuntime\(\)\.exec\s*\(\s*command\s*\)',
        re.I
    )

    # Pattern 4: Suspicious URLs (shell/backdoor domains)
    JSP_SUSPICIOUS_URL = re.compile(
        r'https?://[^"\']*(?:shell|backdoor|c2|rokok|bet|hack|cmd)[^"\']*',
        re.I
    )
    JSP_CLASSLOADER_DEFINE = re.compile(
        r'(defineClass|ClassLoader.*?defineClass|super\.defineClass)\s*\(',
        re.I
    )
    
    JSP_BASE64_CLASSLOAD = re.compile(
        r'(BASE64Decoder|Base64\.getDecoder).*?(defineClass|newInstance|loadClass)',
        re.I | re.DOTALL
    )
    
    JSP_CUSTOM_CLASSLOADER = re.compile(
        r'class\s+\w+\s+extends\s+ClassLoader.*?(defineClass|super\.defineClass)',
        re.I | re.DOTALL
    )
    
    # Runtime execution
    JSP_RUNTIME_EXEC = re.compile(
        r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|new\s+Process',
        re.I
    )
    
    # Reflection-based execution
    JSP_REFLECTION = re.compile(
        r'(Class\.forName|Method\.invoke|getDeclaredMethod|getMethod\s*\(.*?\)\.invoke)',
        re.I
    )
    
    # HttpClient/HTTP request (C2/tunneling)
    JSP_HTTP_CLIENT = re.compile(
        r'(HttpClient|CloseableHttpClient|HttpGet|HttpPost|HttpURLConnection|URL\s*\(.*?\)\.openConnection)',
        re.I
    )
    
    JSP_HTTP_TUNNELING = re.compile(
        r'(HttpClient|HttpGet|HttpPost).*?(request\.getParameter|getInputStream|EntityUtils)',
        re.I | re.DOTALL
    )
    
    # Request parameter execution path
    JSP_REQUEST_EXEC = re.compile(
        r'request\.getParameter.*?(Runtime\.getRuntime|defineClass|Class\.forName|Method\.invoke)',
        re.I | re.DOTALL
    )
    
    # Script execution
    JSP_SCRIPT_ENGINE = re.compile(
        r'ScriptEngineManager|ScriptEngine\.eval|Nashorn',
        re.I
    )
    HARDCODED_BACKDOOR_CMD = re.compile(
        r'(?:String|final\s+String)\s+(?:command|cmd|shell|exec)\s*=\s*["\']'
        r'(?:'
        r'curl\s+-[kK]|'              # curl -k (bỏ yêu cầu https://)
        r'wget\s+(?:-q\s+)?https?://|'
        r'nc\s+-[lnvp]+|'             # netcat
        r'bash\s+-[ic]|sh\s+-[ic]|'
        r'/bin/(?:ba)?sh|cmd\.exe|powershell|'
        r'chmod\s+[0-9]+|'
        r'python\s+-c|perl\s+-e'
        r')',
        re.I
    )

    # Suspicious C2-like domains
    HARDCODED_C2_PATTERN = re.compile(
        r'https?://(?:'
        r'shell\.|c2\.|backdoor\.|admin\.|'
        r'[a-z0-9-]+\.(?:tk|ml|ga|cf|gq)|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}'
        r'[a-z0-9-]+\.[a-z0-9-]+\.com/[^"\']*(?:shell|backdoor|c2)'
        r')',
        re.I
    )

    # Runtime.exec with suspicious variable names
    JSP_RUNTIME_EXEC_SUSPICIOUS = re.compile(
        r'Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:command|cmd|shell|exec)\s*\)',
        re.I
    )

    # HttpClient to external suspicious domains
    JSP_HTTP_EXTERNAL_SUSPICIOUS = re.compile(
        r'(?:HttpGet|HttpPost|URL)\s*\(\s*"https?://(?!localhost|127\.0\.0\.1)[^"]*(?:shell|backdoor|c2)[^"]*"\s*\)',
        re.I
    )

    # JSP compiled class backdoor pattern
    JSP_COMPILED_BACKDOOR = re.compile(
        r'extends\s+(?:HttpJspBase|JspSourceDependent)'
        r'[\s\S]{0,2500}'  # ← Tăng từ 1500 lên 2500
        r'(?:'
        # Runtime.exec variations
        r'Runtime\.getRuntime\(\)\.exec\s*\(\s*command\s*\)|'
        r'Process\s+process\s*=\s*Runtime\.getRuntime\(\)\.exec|'
        r'ProcessBuilder|'
        # Hardcoded command assignments
        r'String\s+command\s*=\s*"(?:curl|wget|nc|bash|sh|cmd|powershell|ls\s+/|dir\s+)|'
        r'final\s+String\s+command\s*=\s*"(?:curl|wget|nc|bash|sh|cmd)'
        r')'
        r'[\s\S]{0,800}'  # ← Tăng từ 500 lên 800
        r'(?:'
        # Suspicious indicators
        r'curl\s+-[kK]|'  # curl with SSL bypass (-k)
        r'wget\s+https?://|'
        r'nc\s+-|bash\s+-|sh\s+-|'
        r'cmd\.exe|powershell|'
        r'ls\s+/(?:home|root|etc)|'  # ← THÊM: Linux enumeration
        r'dir\s+[A-Z]:|'              # ← THÊM: Windows enumeration
        r'https?://[^"\']*(?:shell|backdoor|c2|rokok|bet)'  # ← THÊM: rokok-bet pattern
        r')',
        re.I | re.DOTALL
    )

    # Pattern 2: Direct exec with hardcoded suspicious command (bổ sung)
    JSP_EXEC_HARDCODED_CMD = re.compile(
        r'Runtime\.getRuntime\(\)\.exec\s*\(\s*'
        r'(?:command|cmd|shell|exec|["\'])'  # variable or string literal
        r'[\s\S]{0,200}'  # ← Tăng từ 100 lên 200
        r'(?:'
        r'curl\s+-[kK]|'        # curl -k
        r'wget\s+https?://|'
        r'nc\s+-|bash|sh|cmd\.exe|powershell|'
        r'ls\s+/(?:home|root|etc)|'  # ← THÊM
        r'https?://[^"\']*(?:shell|backdoor|c2|rokok|bet)'  # ← THÊM
        r')',
        re.I | re.DOTALL
    )
    JSCRIPT_ASPX_DIRECTIVE = re.compile(
    r'<%@\s+Page\s+.*?Language\s*=\s*["\']?Jscript["\']?',
    re.I | re.DOTALL
    )

    JSCRIPT_EVAL_ENCODED = re.compile(
        r'(?:\\u0065\\u0076\\u0061\\u006c|\\x65\\x76\\x61\\x6c|eval)\s*\(',
        re.I
    )

    # ============ .NET MEMORY SHELL COMPONENTS ============
    DOTNET_BASE64_FROMSTRING = re.compile(
        r'Convert\s*\.\s*FromBase64String\s*\(',
        re.I
    )

    DOTNET_AES_DECRYPT = re.compile(
        r'AesManaged\s*\(\s*\)\s*\.\s*CreateDecryptor.*?TransformFinalBlock',
        re.I | re.DOTALL
    )

    DOTNET_ASSEMBLY_LOAD = re.compile(
        r'(AppDomain\s*\.\s*CurrentDomain\s*\.\s*Load|Assembly\s*\.\s*Load)\s*\(',
        re.I
    )

    DOTNET_MEMORYSTREAM = re.compile(r'MemoryStream\s*\(', re.I)

    DOTNET_SESSION_CACHE = re.compile(
        r'(Context\s*\.\s*Session|Session)\s*\[\s*["\']',
        re.I
    )

    DOTNET_CREATEINSTANCE = re.compile(
        r'CreateInstance\s*\(\s*["\'][A-Z]{1,5}["\']\s*\)',
        re.I
    )

    DOTNET_WEBSERVICE_DIRECTIVE = re.compile(
        r'<%@\s+WebService\s+Language\s*=\s*["\']?C#["\']?',
        re.I
    )
    # ============ PHP PATTERNS (KEPT) ============
    VAR_VAR_PATTERN = re.compile(r'\$\$\w+|\$\{[\'"]?\w+[\'"]?\}')
    REFLECTION_PATTERN = re.compile(
        r'\b(ReflectionClass|ReflectionMethod|ReflectionFunction|__invoke|__call|__callStatic)\b',
        re.I
    )
    MAGIC_METHOD_PATTERN = re.compile(r'__(invoke|call|callStatic|construct|destruct|get|set)\s*\(', re.I)
    
    ASPX_RUNAT_PATTERN = re.compile(r'runat\s*=\s*["\']server["\']', re.I)
    ASP_CREATEOBJECT = re.compile(r'Server\.CreateObject|WScript\.Shell|Shell\.Application', re.I)
    ASP_SCRIPTING = re.compile(r'(oScriptNet|WScript|Scripting\.FileSystemObject)', re.I)
    
    FILE_WRITE_PATTERN = re.compile(
        r'\b(fopen|file_put_contents|fwrite|move_uploaded_file|copy|rename)\s*\(',
        re.I
    )
    FILE_READ_PATTERN = re.compile(r'\b(file_get_contents|readfile|fread)\s*\(', re.I)
    DB_PATTERN = re.compile(r'\b(mysql_query|mysqli_query|pg_query|sqlite_query|PDO)\b', re.I)
    
    COOKIE_PATTERN = re.compile(r'\$_COOKIE\b', re.I)
    MD5_COOKIE_CHECK = re.compile(r'md5\s*\(\s*@?\$_COOKIE\[.*?\]\s*\)\s*==', re.I)
    
    ERROR_SUPPRESS_EXEC = re.compile(r'@\s*(eval|exec|system|shell_exec|passthru|assert)\s*\(', re.I)
    GOTO_PATTERN = re.compile(r'\bgoto\s+\w+\s*;', re.I)
    BITWISE_CHR = re.compile(r'chr\s*\(\s*\d+\s*\)\s*\^', re.I)
    
    FORM_WITH_TEXTAREA = re.compile(
        r'<form[^>]*>.*?<textarea.*?name\s*=\s*["\']?\w+["\']?',
        re.I | re.DOTALL
    )
    FORM_WITH_FILE_UPLOAD = re.compile(
        r'<form[^>]*enctype\s*=\s*["\']multipart/form-data["\'][^>]*>.*?<input[^>]*type\s*=\s*["\']file["\']',
        re.I | re.DOTALL
    )
    FORM_WITH_FILE_UPLOAD_LOOSE = re.compile(
        r'<form[^>]*\benctype\s*=\s*(?:["\']?multipart/form-data["\']?)[^>]*>'
        r'[\s\S]{0,1500}?<input[^>]*\btype\s*=\s*(?:["\']?file["\']?)',
        re.I | re.DOTALL
    )
    
    # FIXED: Stricter reverse shell pattern
    BEHAVIOR_REVERSE_SHELL = re.compile(
        r'\b(fsockopen|socket_create|socket_connect)\s*\('
        r'[\s\S]{0,300}?'
        r'(/bin/(ba)?sh|bash\s+-i|cmd\.exe\s+/c|powershell\s+-)',
        re.I | re.DOTALL
    )
    
    FSOCKOPEN_PATTERN = re.compile(r'fsockopen\s*\(\s*["\']?[\w\.\-]+["\']?\s*,\s*\d+', re.I)
    SOCKET_CREATE = re.compile(r'socket_create|socket_connect|socket_bind', re.I)
    
    DYNAMIC_INCLUDE = re.compile(
        r'\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        re.I
    )
    UNSERIALIZE_INPUT = re.compile(r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', re.I)
    
    ALPHABET_BUILDER = re.compile(r'\b[a-zA-Z_]\w*\s*=\s*["\'][A-Za-z0-9+/=]{30,}["\']', re.I)
    STRING_INDEX_OBFUSC = re.compile(r'\$\w+\s*\[\s*\d+\s*\]\s*\.', re.I)
    EXTRACT_WITH_INPUT = re.compile(r'\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', re.I)
    GLOBALS_ACCESS = re.compile(r'\$GLOBALS\s*\[', re.I)
    
    LONG_B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{80,}={0,2}')
    HEX_ESCAPE_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}')
    UNICODE_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}')
    OCTAL_ESCAPE_PATTERN = re.compile(r'\\[0-7]{3}')
    COMMENT_OBFUSC_PATTERN = re.compile(r'\w/\*+\*/\w')
    STRING_CONCAT_PATTERN = re.compile(r'["\']\s*\.\s*["\']')
    CHR_CONCAT_PATTERN = re.compile(r'chr\s*\(\s*\d+\s*\)\s*\.', re.I)
    BACKTICK_PATTERN = re.compile(r'`[^`]+`')
    SPECIAL_CHAR_PATTERN = re.compile(r'[^a-zA-Z0-9\s]')
    
    VARIABLE_FUNCTION_CALL = re.compile(r'\$\w+\s*\(\s*\$', re.I)
    INVOKE_PATTERN = re.compile(r'__invoke|->__call|\$this\s*\(', re.I)
    NEWINSTANCE_WITH_INPUT = re.compile(
        r'newInstance\s*\([^\)]*\$_(GET|POST|REQUEST|COOKIE)',
        re.I
    )
    NESTED_FUNCTION_PATTERN = re.compile(r'\$\w+\(\$\w+\(\$\w+\(', re.I)
    FUNCTION_CHAIN_PATTERN = re.compile(r'\w+\s*\(\s*\w+\s*\(\s*\w+\s*\(', re.I)
    DEEP_ARRAY_ACCESS = re.compile(r'\$\w+(\[[^\]]+\]){3,}')
    
    CLASS_WITH_CONSTRUCT_EXEC = re.compile(
        r'class\s+\w+.*?__construct.*?(eval|exec|system|call_user_func)',
        re.I | re.DOTALL
    )
    REFLECTION_NEWINSTANCE = re.compile(
        r'new\s+ReflectionClass.*?newInstance',
        re.I | re.DOTALL
    )
    FAKE_MAGE_CLASS = re.compile(
        r'class\s+(Mage|Varien)_\w+.*?\$_COOKIE.*?(eval|exec|base64_decode)',
        re.I | re.DOTALL
    )
    FAKE_WP_PLUGIN = re.compile(
        r'Plugin\s+Name:.*?(@eval|base64_decode.*?eval)',
        re.I | re.DOTALL
    )
    
    # FN Patch patterns
    SUPERGLOBAL_VAR_CALL = re.compile(r'@?\$_\s*\(|@?\$__+\s*\(', re.I)
    ASSIGN_FROM_INPUT_THEN_CALL = re.compile(
        r'\$([a-zA-Z_][a-zA-Z0-9_]{0,3})\s*=\s*@?\$_(GET|POST|REQUEST|COOKIE)\b'
        r'[\s\S]{0,300}?@?\$\1\s*\(',
        re.I
    )
    COOKIE_HASH_GATE_DYNAMIC_CALL = re.compile(
        r'md5\s*\(\s*@?\$_COOKIE\[.*?\]\s*\)\s*==={0,2}\s*["\'][0-9a-f]{16,32}["\']'
        r'[\s\S]{0,600}?@?\$_\s*\(',
        re.I
    )
    
    # Benign data indicators
    PHP_SERIALIZED_TOKEN = re.compile(r'\b(?:a|O|s|i|b|d):\d+:', re.I)
    SVG_BLOB = re.compile(r'<svg\b', re.I)
    
    # JAVA_RUNTIME_EXEC = re.compile(
    #     r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|new\s+Process',
    #     re.I
    # )
    # JAVA_REFLECTION = re.compile(r'Class\.forName|Method\.invoke|getDeclaredMethod', re.I)
    PYTHON_EXEC = re.compile(r'\b(exec|eval|compile|__import__)\s*\(', re.I)
    PYTHON_OS_SYSTEM = re.compile(
        r'(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)',
        re.I
    )
    
    DECODE_CHAIN = re.compile(
        r'(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*'
        r'(base64_decode|gzinflate|gzuncompress|str_rot13)',
        re.I
    )
    REGEX_EXEC_SINK = re.compile(r'preg_replace\s*\(\s*["\'][^"\']*e[^"\']*["\']', re.I)
    
    # Behavioral patterns
    BEHAVIOR_INPUT_DECODE_EXEC = re.compile(
        r'\$_(GET|POST|REQUEST|COOKIE).*?'
        r'(base64_decode|gzinflate|gzuncompress|str_rot13).*?'
        r'(eval|assert|system|exec|shell_exec)',
        re.I | re.DOTALL
    )
    BEHAVIOR_PASSWORD_BACKDOOR = re.compile(
        r'(?:'
        # Original: if ($_POST['pass'] == "xxx")
        r'if\s*\(\s*\$_(POST|REQUEST|COOKIE)\[.*?(pass|pwd|key|auth).*?\]\s*===?'
        r'|'
        # Negation: if ($_POST['pass'] != "xxx")
        r'if\s*\(\s*\$_(POST|REQUEST|COOKIE)\[.*?(pass|pwd|key|auth).*?\]\s*!==?'
        r'|'
        # Variable comparison: if ($pass === $auth_pass)
        r'if\s*\([^)]*\$_(POST|REQUEST|COOKIE)\[.*?(pass|pwd|key|auth).*?\][^)]*===?\s*\$\w+'
        r'|'
        # Negation with variable: if ($pass !== $auth_pass)
        r'if\s*\([^)]*\$_(POST|REQUEST|COOKIE)\[.*?(pass|pwd|key|auth).*?\][^)]*!==?\s*\$\w+'
        r'|'
        # Session + POST check: if (!isset($_SESSION) || $_POST['pass'] != $x)
        r'if\s*\([^)]*\$_SESSION[^)]*\|\|[^)]*\$_(POST|REQUEST|COOKIE)\[.*?(pass|pwd|key|auth).*?\]\s*!==?'
        r')',
        re.I
    )
    BEHAVIOR_RAWBODY_BACKDOOR = re.compile(r'php://input|php://stdin', re.I)
    BEHAVIOR_SQL_BACKDOOR = re.compile(
        r'(select|insert|update|delete).{0,200}\$_(GET|POST|REQUEST|COOKIE)',
        re.I | re.DOTALL
    )
    BEHAVIOR_OBFUSC_EXEC = re.compile(
        r'(chr\s*\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\[0-7]{3}).{0,200}'
        r'(eval|assert|system|exec|shell_exec)',
        re.I | re.DOTALL
    )
    BEHAVIOR_COOKIE_EXEC = re.compile(
        r'\$_COOKIE.{0,150}(eval|assert|system|exec|shell_exec|passthru)',
        re.I | re.DOTALL
    )
    BEHAVIOR_DATA_EXFIL = re.compile(r'(curl_exec|file_get_contents).{0,120}http', re.I | re.DOTALL)
    BEHAVIOR_DROPPER = re.compile(
        r'(move_uploaded_file|file_put_contents|fopen|fwrite).{0,200}\$_(FILES|POST|REQUEST)',
        re.I | re.DOTALL
    )
    BEHAVIOR_FILE_MANAGER = re.compile(
        r'(scandir|opendir|readdir|unlink|chmod|chown).{0,200}\$_(GET|POST|REQUEST)',
        re.I | re.DOTALL
    )
    BEHAVIOR_UPLOAD_CHMOD = re.compile(r'move_uploaded_file.{0,500}chmod', re.I | re.DOTALL)
    
    EXEC_COMMENT_SPLIT = re.compile(
        r'\b(eval|assert|system|exec|shell_exec|passthru)\b\s*/\*[\s\S]{0,80}?\*/\s*\(',
        re.I | re.DOTALL
    )
    ASSIGN_FROM_INPUT_THEN_EXEC = re.compile(
        r'\$([a-zA-Z_][a-zA-Z0-9_]{0,15})\s*=\s*'
        r'(?:@?\$_(GET|POST|REQUEST|COOKIE|FILES)\b|filter_input\s*\(|filter_var\s*\(|'
        r'Request\.(?:Form|QueryString|Params|Cookies)\s*\[)'
        r'[\s\S]{0,500}?\b(eval|assert|system|exec|shell_exec|passthru)\b'
        r'\s*(?:/\*[\s\S]{0,80}?\*/\s*)*\(\s*(?:\w+\s*\(\s*){0,3}\$\1\b',
        re.I | re.DOTALL
    )
    BEHAVIOR_FILTERINPUT_EXEC = re.compile(
        r'(filter_input\s*\(|filter_var\s*\(|Request\.(?:Form|QueryString|Params|Cookies)\s*\[)'
        r'[\s\S]{0,350}?\b(eval|assert|system|exec|shell_exec|passthru)\b'
        r'\s*(?:/\*[\s\S]{0,80}?\*/\s*)*\(',
        re.I | re.DOTALL
    )
    BEHAVIOR_SQLMAP_UPLOADER = re.compile(
        r'(sqlmap\s+file\s+uploader|File\s+uploaded|MAX_FILE_SIZE)'
        r'[\s\S]{0,1200}?(move_uploaded_file|\$_FILES|\$HTTP_POST_FILES)',
        re.I | re.DOTALL
    )
    BEHAVIOR_ARBITRARY_UPLOAD_PATH = re.compile(
        r'\$\w{1,20}\s*=\s*\$_(REQUEST|POST|GET)\s*\[\s*["\']uploadDir["\']\s*\]'
        r'[\s\S]{0,600}?move_uploaded_file',
        re.I | re.DOTALL
    )
    
    # ============ FRAMEWORK SIGNATURES ============
    FRAMEWORK_SIGNATURES = {
        'cakephp': re.compile(r'namespace\s+Cake\\|class\s+\w+\s+extends\s+AppController|use\s+Cake\\', re.I),
        'joomla': re.compile(r'defined\s*\(\s*["\']_JEXEC["\']|JFactory::|jimport\s*\(|class\s+\w+\s+extends\s+JController', re.I),
        'k2': re.compile(r'K2HelperUtilities|class\s+K2\w+|JTable::getInstance\s*\(\s*["\']K2', re.I),
        'elfinder': re.compile(r'class\s+elFinder|elFinder::.*?driver|connector\.php.*?elFinder', re.I),
        'wordpress': re.compile(r'defined\s*\(\s*["\']ABSPATH["\']|get_option\s*\(|wp_enqueue_script|add_action\s*\(', re.I),
        'drupal': re.compile(r'drupal_bootstrap|module_invoke|drupal_get_path|db_query', re.I),
        'laravel': re.compile(r'namespace\s+App\\|use\s+Illuminate\\|class\s+\w+\s+extends\s+Controller', re.I),
        'symfony': re.compile(r'namespace\s+Symfony\\|use\s+Symfony\\|extends\s+ContainerAware', re.I),
        'sharepoint': re.compile(r'Microsoft\.SharePoint|SPWeb|SPSite|ApplicationPage', re.I),
        'jquery': re.compile(r'jQuery\.fn\.jquery|@version\s+\d+\.\d+\.\d+.*?jQuery', re.I),
        'angular': re.compile(r'angular\.module\(|ng-app|@angular/core', re.I),
        'react': re.compile(r'React\.createElement|from\s+["\']react["\']|@jsx', re.I),
        'vue': re.compile(r'new\s+Vue\(|Vue\.component|@vue/cli', re.I),
    }
    
    @staticmethod
    @lru_cache(maxsize=128)
    def calculate_entropy(text: str) -> float:
        """Cached entropy calculation"""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in counter.values())
    
    @staticmethod
    def normalize_code(code: str) -> str:
        """Decode unicode/hex escapes"""
        if not code:
            return code
        
        normalized = code
        try:
            normalized = re.sub(
                r'\\u([0-9a-fA-F]{4})',
                lambda m: chr(int(m.group(1), 16)),
                normalized
            )
        except:
            pass
        
        try:
            normalized = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                normalized
            )
        except:
            pass
        
        return normalized
    
    @staticmethod
    def strip_strings_and_comments(code: str):
        """Return (code_without_strings_and_comments, string_literal_ratio)"""
        if not code:
            return "", 0.0
        
        original_len = max(len(code), 1)
        tmp = code
        
        # Remove comments
        tmp = re.sub(r"<%--[\s\S]*?--%>", " ", tmp)
        tmp = re.sub(r"/\*[\s\S]*?\*/", " ", tmp)
        tmp = re.sub(r"//.*?$", " ", tmp, flags=re.MULTILINE)
        tmp = re.sub(r"#.*?$", " ", tmp, flags=re.MULTILINE)
        
        string_len = 0
        
        # C# verbatim strings
        verbatim = re.compile(r'@\"(?:[^\"]|\"\")*\"', re.DOTALL)
        for mm in verbatim.finditer(tmp):
            string_len += len(mm.group(0))
        tmp = verbatim.sub(" ", tmp)
        
        # Normal strings
        normal = re.compile(r'(\"(?:\\\\.|[^\"\\\\])*\"|\'(?:\\\\.|[^\'\\\\])*\')', re.DOTALL)
        for mm in normal.finditer(tmp):
            string_len += len(mm.group(0))
        tmp = normal.sub(" ", tmp)
        
        ratio = float(string_len) / float(original_len)
        return tmp, ratio
    
    def safe_read(self, filepath: str) -> Optional[str]:
        """Enhanced file reading with UTF-16 support for ASPX"""
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
            
            # Try UTF-8 first
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                pass
            
            # Try UTF-16 variants (common for ASPX)
            for encoding in ['utf-16', 'utf-16-le', 'utf-16-be']:
                try:
                    # Strip null bytes that might interfere with regex
                    decoded = raw.decode(encoding)
                    return decoded.replace('\x00', '')
                except:
                    continue
            
            # Fallback to latin-1
            return raw.decode('latin-1')
        except Exception:
            return None
    
    def _detect_framework(self, code: str, filepath: str) -> Optional[str]:
        """Detect known frameworks"""
        code_sample = code[:5000] if len(code) > 5000 else code
        
        for name, pattern in self.FRAMEWORK_SIGNATURES.items():
            if pattern.search(code_sample):
                return name
        
        return None
    
    def _optimized_pattern_search(self, code: str, normalized_code: str, filepath: str) -> Dict:
        """Single-pass pattern search"""
        results = {}
        
        is_aspx = filepath.lower().endswith(('.aspx', '.ascx', '.asax', '.ashx', '.asmx'))
        
        # ASPX: Distinguish databinding Eval from code Eval
        if is_aspx:
            databinding_evals = len(self.ASPX_DATABINDING_EVAL.findall(code))  # Search in original code
            
            # Code eval: not in databinding context
            code_eval_pattern = re.compile(r'(?<!<%[#=]\s)\beval\s*\(', re.I)
            code_evals = len(code_eval_pattern.findall(normalized_code))
            results['aspx_databinding_eval_count'] = databinding_evals
            results['aspx_code_eval_count'] = code_evals
            
            # Only count code evals as exec
            exec_matches = list(self.EXEC_PATTERN.finditer(normalized_code))
            # Filter out databinding evals
            exec_matches = [m for m in exec_matches if 'eval' not in m.group(0).lower() or code_evals > 0]
        else:
            exec_matches = list(self.EXEC_PATTERN.finditer(normalized_code))
            results['aspx_databinding_eval_count'] = 0
            results['aspx_code_eval_count'] = 0
        
        results['exec_matches'] = exec_matches
        results['exec_positions'] = [m.start() for m in exec_matches]
        
        decode_matches = list(self.DECODE_PATTERN.finditer(normalized_code))
        results['decode_matches'] = decode_matches
        results['decode_positions'] = [m.start() for m in decode_matches]
        
        input_matches = list(self.INPUT_PATTERN.finditer(normalized_code))
        results['input_matches'] = input_matches
        results['input_positions'] = [m.start() for m in input_matches]
        
        dynamic_exec_matches = list(self.DYNAMIC_EXEC_PATTERN.finditer(normalized_code))
        results['dynamic_exec_matches'] = dynamic_exec_matches
        
        results['has_reflection'] = bool(self.REFLECTION_PATTERN.search(normalized_code))
        results['has_magic_method'] = bool(self.MAGIC_METHOD_PATTERN.search(normalized_code))
        
        # ASPX patterns
        results['has_jscript_directive'] = bool(self.JSCRIPT_ASPX_DIRECTIVE.search(code))
        results['has_jscript_eval_encoded'] = bool(self.JSCRIPT_EVAL_ENCODED.search(normalized_code))

        # .NET Memory Shell components
        results['has_dotnet_frombase64'] = bool(self.DOTNET_BASE64_FROMSTRING.search(normalized_code))
        results['has_dotnet_aes_decrypt'] = bool(self.DOTNET_AES_DECRYPT.search(normalized_code))
        results['has_dotnet_assembly_load'] = bool(self.DOTNET_ASSEMBLY_LOAD.search(normalized_code))
        results['has_dotnet_memorystream'] = bool(self.DOTNET_MEMORYSTREAM.search(normalized_code))
        results['has_dotnet_session_cache'] = bool(self.DOTNET_SESSION_CACHE.search(normalized_code))
        results['has_dotnet_createinstance'] = bool(self.DOTNET_CREATEINSTANCE.search(normalized_code))
        results['has_dotnet_webservice'] = bool(self.DOTNET_WEBSERVICE_DIRECTIVE.search(code))
        results['has_aspx_exec'] = bool(self.ASPX_EXEC_PATTERN.search(normalized_code))
        results['has_aspx_runat'] = bool(self.ASPX_RUNAT_PATTERN.search(normalized_code))
        results['has_asp_createobject'] = bool(self.ASP_CREATEOBJECT.search(normalized_code))
        results['has_asp_scripting'] = bool(self.ASP_SCRIPTING.search(normalized_code))
        
        # NEW: ASPX enhanced patterns
        results['has_aspx_file_write'] = bool(self.ASPX_FILE_WRITE.search(normalized_code))
        results['has_aspx_file_upload'] = bool(self.ASPX_FILE_UPLOAD.search(normalized_code))
        results['has_aspx_winapi'] = bool(self.ASPX_WINAPI_IMPORT.search(normalized_code))
        results['has_aspx_named_pipe'] = bool(self.ASPX_NAMED_PIPE.search(normalized_code))
        results['has_aspx_privilege_esc'] = bool(self.ASPX_PRIVILEGE_ESCALATION.search(normalized_code))
        results['has_jsp_classloader'] = bool(self.JSP_CLASSLOADER_DEFINE.search(normalized_code))
        results['has_jsp_base64_classload'] = bool(self.JSP_BASE64_CLASSLOAD.search(normalized_code))
        results['has_jsp_custom_classloader'] = bool(self.JSP_CUSTOM_CLASSLOADER.search(normalized_code))
        results['has_jsp_runtime_exec'] = bool(self.JSP_RUNTIME_EXEC.search(normalized_code))
        results['has_jsp_reflection'] = bool(self.JSP_REFLECTION.search(normalized_code))
        results['has_jsp_http_client'] = bool(self.JSP_HTTP_CLIENT.search(normalized_code))
        results['has_jsp_script_engine'] = bool(self.JSP_SCRIPT_ENGINE.search(normalized_code))
        results['has_hardcoded_backdoor_cmd'] = bool(self.HARDCODED_BACKDOOR_CMD.search(normalized_code))
        results['has_hardcoded_c2'] = bool(self.HARDCODED_C2_PATTERN.search(normalized_code))
        results['has_jsp_runtime_suspicious'] = bool(self.JSP_RUNTIME_EXEC_SUSPICIOUS.search(normalized_code))
        results['has_jsp_http_external_suspicious'] = bool(self.JSP_HTTP_EXTERNAL_SUSPICIOUS.search(normalized_code))
        results['has_jsp_compiled_class'] = bool(self.JSP_COMPILED_CLASS.search(normalized_code))
        results['has_jsp_hardcoded_command'] = bool(self.JSP_HARDCODED_COMMAND.search(normalized_code))
        results['has_jsp_runtime_exec_command'] = bool(self.JSP_RUNTIME_EXEC_COMMAND.search(normalized_code))
        results['has_jsp_suspicious_url_pattern'] = bool(self.JSP_SUSPICIOUS_URL.search(normalized_code))
        
        # Combined detection: All 3 components must be present for compiled JSP backdoor
        results['has_jsp_compiled_backdoor'] = bool(
            results['has_jsp_compiled_class'] and
            results['has_jsp_runtime_exec_command'] and
            results['has_jsp_hardcoded_command']
        )
        results['has_jsp_linux_enum'] = bool(re.search(
            r'String\s+command\s*=\s*"ls\s+/(?:home|root|etc|var)',
            normalized_code,
            re.I
        ))

        results['has_jsp_hardcoded_curl_k'] = bool(re.search(
            r'curl\s+-[kK]\s+https?://',
            normalized_code,
            re.I
        ))
        results['has_jsp_exec_hardcoded_cmd'] = bool(self.JSP_EXEC_HARDCODED_CMD.search(normalized_code))
        # Framework detection
        
        results['detected_framework'] = self._detect_framework(code, filepath)
        
        return results
    
    def extract_features_from_code(self, code: str, filepath: str = "") -> Optional[Dict[str, float]]:
        """Enhanced extraction with ASPX support and FP reduction"""
        if not code or len(code) < 20:
            return None
        
        features = {"_version": self.VERSION}
        
        normalized_code = self.normalize_code(code)
        
        lines = code.splitlines()
        line_count = max(len(lines), 1)
        length = max(len(code), 1)
        code_lower = code.lower()
        
        # Continuation of extract_features_from_code method...
        
        stripped_code, string_literal_ratio = self.strip_strings_and_comments(code)
        stripped_len = max(len(stripped_code), 1)
        features["string_literal_ratio"] = float(string_literal_ratio)
        features["entropy_nostrings"] = self.calculate_entropy(stripped_code)
        features["special_char_ratio_nostrings"] = len(self.SPECIAL_CHAR_PATTERN.findall(stripped_code)) / stripped_len
        
        cache = self._optimized_pattern_search(code, normalized_code, filepath)
        
        exec_matches = cache['exec_matches']
        decode_matches = cache['decode_matches']
        input_matches = cache['input_matches']
        exec_positions = cache['exec_positions']
        decode_positions = cache['decode_positions']
        input_positions = cache['input_positions']
        
        has_input = len(input_matches) > 0
        has_exec = len(exec_matches) > 0
        has_decode = len(decode_matches) > 0
        has_reflection = cache['has_reflection']
        has_regex_exec = bool(self.REGEX_EXEC_SINK.search(normalized_code))
        features["has_regex_exec"] = int(has_regex_exec)
        features["exec_path_regex"] = int(has_input and has_regex_exec)
        tunneling_components = cache.get('aspx_tunneling_components', {})
        has_socket = tunneling_components.get('socket', False)
        has_connect = tunneling_components.get('connect', False)
        has_req_binary = tunneling_components.get('req_binary', False)
        has_resp_binary = tunneling_components.get('resp_binary', False)
        has_proxy_hint = tunneling_components.get('proxy_hint', False)
        
        tunneling_score = 0.0
        if has_socket:
            tunneling_score += 1.0
        if has_connect:
            tunneling_score += 1.0
        if has_req_binary:
            tunneling_score += 1.0
        if has_resp_binary:
            tunneling_score += 1.0
        if has_proxy_hint:
            tunneling_score += 0.5
        
        features["aspx_tunneling_score"] = float(tunneling_score)
        # Framework detection
        features["detected_framework"] = cache['detected_framework'] or ""
        features["is_known_framework"] = int(bool(cache['detected_framework']))
        
        # Core features
        features["has_exec_function"] = int(has_exec)
        features["exec_func_count"] = len(exec_matches)
        features["has_decode_function"] = int(has_decode)
        features["decode_func_count"] = len(decode_matches)
        features["has_input_access"] = int(has_input)
        features["input_count"] = len(input_matches)
        features["has_dynamic_exec"] = int(len(cache['dynamic_exec_matches']) > 0)
        
        # NEW: ASPX databinding vs code eval
        features["aspx_databinding_eval_count"] = cache['aspx_databinding_eval_count']
        features["aspx_code_eval_count"] = cache['aspx_code_eval_count']
        
        # Benign data/blob indicators
        low_exec_signals = int(not (features.get("has_exec_function", 0) or 
                                     features.get("has_decode_function", 0) or 
                                     features.get("has_dynamic_exec", 0)))
        
        has_svg_blob = (bool(self.SVG_BLOB.search(code)) and 
                        (code_lower.count("<path") >= 2 or code_lower.count("d=\"") >= 3) and 
                        length > 400)
        
        serialized_tokens = len(self.PHP_SERIALIZED_TOKEN.findall(code))
        has_serialized_blob = serialized_tokens >= 25 and length > 600
        has_large_lang_array = (code.count("=>") >= 200 and length > 5000 and low_exec_signals)
        
        features["has_svg_blob"] = int(has_svg_blob)
        features["has_serialized_blob"] = int(has_serialized_blob)
        features["has_large_lang_array"] = int(has_large_lang_array)
        features["benign_data_blob_score"] = min(1.0, (
            features["has_svg_blob"] * 0.45 + 
            features["has_serialized_blob"] * 0.45 + 
            features["has_large_lang_array"] * 0.35
        ))
        
        # Additional patterns
        features["has_var_vars"] = int(bool(self.VAR_VAR_PATTERN.search(normalized_code)))
        features["has_reflection"] = int(has_reflection)
        features["has_magic_method"] = int(cache['has_magic_method'])
        
        features["has_aspx_exec"] = int(cache['has_aspx_exec'])
        features["has_aspx_runat"] = int(cache['has_aspx_runat'])
        features["has_asp_createobject"] = int(cache['has_asp_createobject'])
        features["has_asp_scripting"] = int(cache['has_asp_scripting'])
        
        # NEW: ASPX enhanced features
        features["has_aspx_file_write"] = int(cache['has_aspx_file_write'])
        features["has_aspx_file_upload"] = int(cache['has_aspx_file_upload'])
        features["has_aspx_winapi"] = int(cache['has_aspx_winapi'])
        features["has_aspx_named_pipe"] = int(cache['has_aspx_named_pipe'])
        features["has_aspx_privilege_esc"] = int(cache['has_aspx_privilege_esc'])

        features["has_jsp_classloader"] = int(cache['has_jsp_classloader'])
        features["has_jsp_base64_classload"] = int(cache['has_jsp_base64_classload'])
        features["has_jsp_compiled_class"] = int(cache.get('has_jsp_compiled_class', False))
        features["has_jsp_hardcoded_command"] = int(cache.get('has_jsp_hardcoded_command', False))
        features["has_jsp_runtime_exec_command"] = int(cache.get('has_jsp_runtime_exec_command', False))
        features["has_jsp_suspicious_url_pattern"] = int(cache.get('has_jsp_suspicious_url_pattern', False))
        features["has_jsp_compiled_backdoor"] = int(cache.get('has_jsp_compiled_backdoor', False))
        features["has_jsp_custom_classloader"] = int(cache['has_jsp_custom_classloader'])
        features["has_jsp_runtime_exec"] = int(cache['has_jsp_runtime_exec'])
        features["has_jsp_reflection"] = int(cache['has_jsp_reflection'])
        features["has_jsp_http_client"] = int(cache['has_jsp_http_client'])
        features["has_jsp_script_engine"] = int(cache['has_jsp_script_engine'])
        features["has_jscript_directive"] = int(cache['has_jscript_directive'])
        features["has_jscript_eval_encoded"] = int(cache['has_jscript_eval_encoded'])

        features["has_hardcoded_backdoor_cmd"] = int(cache['has_hardcoded_backdoor_cmd'])
        features["has_hardcoded_c2"] = int(cache['has_hardcoded_c2'])
        features["has_jsp_runtime_suspicious"] = int(cache['has_jsp_runtime_suspicious'])
        features["has_jsp_http_external_suspicious"] = int(cache['has_jsp_http_external_suspicious'])
        features["has_jsp_compiled_backdoor"] = int(cache['has_jsp_compiled_backdoor'])
        features["has_jsp_exec_hardcoded_cmd"] = int(cache['has_jsp_exec_hardcoded_cmd'])
        features["has_jsp_linux_enum"] = int(cache.get('has_jsp_linux_enum', False))
        features["has_jsp_hardcoded_curl_k"] = int(cache.get('has_jsp_hardcoded_curl_k', False))
        # .NET Memory Shell features
        features["has_dotnet_frombase64"] = int(cache['has_dotnet_frombase64'])
        features["has_dotnet_aes_decrypt"] = int(cache['has_dotnet_aes_decrypt'])
        features["has_dotnet_assembly_load"] = int(cache['has_dotnet_assembly_load'])
        features["has_dotnet_memorystream"] = int(cache['has_dotnet_memorystream'])
        features["has_dotnet_session_cache"] = int(cache['has_dotnet_session_cache'])
        features["has_dotnet_createinstance"] = int(cache['has_dotnet_createinstance'])
        features["has_dotnet_webservice"] = int(cache['has_dotnet_webservice'])
        # Backdoor patterns
        features["has_md5_cookie_check"] = int(bool(self.MD5_COOKIE_CHECK.search(normalized_code)))
        features["has_fake_mage_class"] = int(bool(self.FAKE_MAGE_CLASS.search(normalized_code)))
        features["has_fake_wp_plugin"] = int(bool(self.FAKE_WP_PLUGIN.search(normalized_code)))
        features["has_class_construct_exec"] = int(bool(self.CLASS_WITH_CONSTRUCT_EXEC.search(normalized_code)))
        
        # Obfuscation patterns
        features["has_long_base64"] = int(bool(self.LONG_B64_PATTERN.search(normalized_code)))
        features["long_base64_count"] = len(self.LONG_B64_PATTERN.findall(normalized_code))
        features["has_hex_escape"] = int(bool(self.HEX_ESCAPE_PATTERN.search(code)))
        features["has_unicode_escape"] = int(bool(self.UNICODE_ESCAPE_PATTERN.search(code)))
        features["has_octal_escape"] = int(bool(self.OCTAL_ESCAPE_PATTERN.search(code)))
        features["has_comment_obfusc"] = int(bool(self.COMMENT_OBFUSC_PATTERN.search(normalized_code)))
        features["has_string_concat"] = int(bool(self.STRING_CONCAT_PATTERN.search(normalized_code)))
        features["has_chr_concat"] = int(bool(self.CHR_CONCAT_PATTERN.search(normalized_code)))
        features["has_bitwise_chr"] = int(bool(self.BITWISE_CHR.search(normalized_code)))
        features["has_string_index_obfusc"] = int(bool(self.STRING_INDEX_OBFUSC.search(normalized_code)))
        features["has_alphabet_builder"] = int(bool(self.ALPHABET_BUILDER.search(normalized_code)))
        features["has_decode_chain"] = int(bool(self.DECODE_CHAIN.search(normalized_code)))
        
        # File ops patterns
        features["has_file_write_ops"] = int(bool(self.FILE_WRITE_PATTERN.search(normalized_code)))
        features["has_file_read_ops"] = int(bool(self.FILE_READ_PATTERN.search(normalized_code)))
        features["has_db_ops"] = int(bool(self.DB_PATTERN.search(normalized_code)))
        
        # Network patterns
        features["has_fsockopen"] = int(bool(self.FSOCKOPEN_PATTERN.search(normalized_code)))
        features["has_socket_create"] = int(bool(self.SOCKET_CREATE.search(normalized_code)))
        
        # Form patterns
        features["has_form_textarea"] = int(bool(self.FORM_WITH_TEXTAREA.search(normalized_code)))
        features["has_form_file_upload"] = int(bool(self.FORM_WITH_FILE_UPLOAD.search(normalized_code)))
        features["has_form_file_upload_loose"] = int(bool(self.FORM_WITH_FILE_UPLOAD_LOOSE.search(normalized_code)))
        features["behavior_form_file_upload_loose"] = int(bool(
            features["has_form_file_upload_loose"] and features["has_file_write_ops"]
        ))
        
        # Dynamic patterns
        features["has_dynamic_include"] = int(bool(self.DYNAMIC_INCLUDE.search(normalized_code)))
        features["has_unserialize_input"] = int(bool(self.UNSERIALIZE_INPUT.search(normalized_code)))
        
        # Stealth patterns
        features["has_goto"] = int(bool(self.GOTO_PATTERN.search(normalized_code)))
        features["has_backticks"] = int(bool(self.BACKTICK_PATTERN.search(normalized_code)))
        features["has_error_suppress_exec"] = int(bool(self.ERROR_SUPPRESS_EXEC.search(normalized_code)))
        
        # Cross-language patterns
        features["has_java_runtime_exec"] = int(bool(self.JSP_RUNTIME_EXEC.search(normalized_code)))
        features["has_java_reflection"] = int(bool(self.JSP_REFLECTION.search(normalized_code)))
        features["has_python_exec"] = int(bool(self.PYTHON_EXEC.search(normalized_code)))
        features["has_python_os_system"] = int(bool(self.PYTHON_OS_SYSTEM.search(normalized_code)))
        
        # Densities
        features["input_density"] = len(input_matches) / line_count
        features["exec_density"] = len(exec_matches) / line_count
        features["decode_density"] = len(decode_matches) / line_count
        features["dynamic_exec_density"] = len(cache['dynamic_exec_matches']) / line_count
        
        # Distance metrics
        if has_input and has_exec:
            features["input_exec_distance"] = min(
                abs(exec_positions[0] - input_positions[0]) / length, 1.0
            )
            all_positions = input_positions + exec_positions
            features["short_input_exec_distance"] = int(
                len(all_positions) >= 2 and max(all_positions) - min(all_positions) < 300
            )
        else:
            features["input_exec_distance"] = 1.0
            features["short_input_exec_distance"] = 0
        
        # Advanced patterns
        features["has_variable_function_call"] = int(bool(self.VARIABLE_FUNCTION_CALL.search(normalized_code)))
        features["has_superglobal_var_call"] = int(bool(self.SUPERGLOBAL_VAR_CALL.search(normalized_code)))
        features["has_assign_input_then_call"] = int(bool(self.ASSIGN_FROM_INPUT_THEN_CALL.search(normalized_code)))
        features["has_assign_input_then_exec"] = int(bool(self.ASSIGN_FROM_INPUT_THEN_EXEC.search(normalized_code)))
        features["has_exec_comment_split"] = int(bool(self.EXEC_COMMENT_SPLIT.search(normalized_code)))
        features["has_invoke_pattern"] = int(bool(self.INVOKE_PATTERN.search(normalized_code)))
        features["has_newinstance_with_input"] = int(bool(self.NEWINSTANCE_WITH_INPUT.search(normalized_code)))
        features["has_nested_functions"] = int(bool(self.NESTED_FUNCTION_PATTERN.search(normalized_code)))
        features["has_function_chain"] = int(bool(self.FUNCTION_CHAIN_PATTERN.search(normalized_code)))
        
        deep_array_matches = self.DEEP_ARRAY_ACCESS.findall(normalized_code)
        features["deep_array_access_count"] = len(deep_array_matches)
        features["has_deep_array_access"] = int(bool(deep_array_matches))
        features["has_reflection_newinstance"] = int(bool(self.REFLECTION_NEWINSTANCE.search(normalized_code)))
        
        # Statistical features
        features["entropy"] = self.calculate_entropy(code)
        features["avg_line_length"] = length / line_count
        features["log_code_size"] = math.log1p(length)
        features["digit_ratio"] = sum(1 for c in code if c.isdigit()) / length
        features["special_char_ratio"] = sum(1 for c in code if (not c.isalnum()) and (not c.isspace())) / length
        features["whitespace_ratio"] = sum(1 for c in code if c.isspace()) / length
        
        # === BEHAVIORAL FEATURES ===
        behavior_chain = bool(self.BEHAVIOR_INPUT_DECODE_EXEC.search(normalized_code))
        features["behavior_input_decode_exec"] = int(behavior_chain)
        
        behavior_password = bool(self.BEHAVIOR_PASSWORD_BACKDOOR.search(normalized_code))
        features["behavior_password_backdoor"] = int(behavior_password)
        
        behavior_sql = bool(self.BEHAVIOR_SQL_BACKDOOR.search(normalized_code))
        features["behavior_sql_backdoor"] = int(behavior_sql)
        
        behavior_obfusc = bool(self.BEHAVIOR_OBFUSC_EXEC.search(normalized_code))
        features["behavior_obfuscated_exec"] = int(behavior_obfusc)
        
        behavior_cookie = bool(self.BEHAVIOR_COOKIE_EXEC.search(normalized_code))
        features["behavior_cookie_exec"] = int(behavior_cookie)
        
        behavior_cookie_hash_gate = bool(self.COOKIE_HASH_GATE_DYNAMIC_CALL.search(normalized_code))
        features["behavior_cookie_hash_gate_dyn_call"] = int(behavior_cookie_hash_gate)
        
        # NEW: ASPX-specific behaviors
        behavior_aspx_file_manager = bool(self.ASPX_FILE_MANAGER.search(normalized_code))
        features["behavior_aspx_file_manager"] = int(behavior_aspx_file_manager)
        
        # NEW: Enhanced ASPX tunneling - requires multiple components
        tunneling_components = cache.get('aspx_tunneling_components', {})
        has_socket = tunneling_components.get('socket', False)
        has_connect = tunneling_components.get('connect', False)
        has_req_binary = tunneling_components.get('req_binary', False)
        has_resp_binary = tunneling_components.get('resp_binary', False)
        has_proxy_hint = tunneling_components.get('proxy_hint', False)
        
        # Tunneling score calculation
        tunneling_score = 0
        if has_socket:
            tunneling_score += 1
        if has_connect:
            tunneling_score += 1
        if has_req_binary:
            tunneling_score += 1
        if has_resp_binary:
            tunneling_score += 1
        if has_proxy_hint:
            tunneling_score += 0.5  # Bonus hint
        
        # Behavior triggered when >= 3 components present (or 2.5 with proxy hint)
        behavior_aspx_tunneling = (features.get("aspx_tunneling_score", 0) >= 3.0)
        features["behavior_aspx_tunneling"] = int(behavior_aspx_tunneling)
        # behavior_aspx_tunneling = (tunneling_score >= 3.0)
        # features["behavior_aspx_tunneling"] = int(behavior_aspx_tunneling)
        # features["aspx_tunneling_score"] = tunneling_score
        
        behavior_aspx_privilege_pipe = bool(
            cache['has_aspx_named_pipe'] and cache['has_aspx_privilege_esc']
        )
        features["behavior_aspx_privilege_pipe"] = int(behavior_aspx_privilege_pipe)
        
        behavior_aspx_process_shell = bool(
            features.get("has_aspx_exec", 0) and 
            bool(self.ASPX_REQUEST_INPUT.search(normalized_code)) and 
            bool(self.ASPX_PROCESS_PIPE.search(normalized_code))
        )
        features["behavior_aspx_process_shell"] = int(behavior_aspx_process_shell)

        behavior_jsp_memory_shell = bool(
            cache['has_jsp_classloader'] and 
            (cache['has_jsp_base64_classload'] or cache['has_jsp_custom_classloader'])
        )
        features["behavior_jsp_memory_shell"] = int(behavior_jsp_memory_shell)
        
        behavior_jsp_request_exec = bool(self.JSP_REQUEST_EXEC.search(normalized_code))
        features["behavior_jsp_request_exec"] = int(behavior_jsp_request_exec)
        
        behavior_jsp_http_tunneling = bool(self.JSP_HTTP_TUNNELING.search(normalized_code))
        features["behavior_jsp_http_tunneling"] = int(behavior_jsp_http_tunneling)
        behavior_jsp_hardcoded_backdoor = bool(
            # Method 1: NEW - Compiled JSP with all components
            cache.get('has_jsp_compiled_backdoor', False) or
            
            # Method 2: Compiled class + hardcoded command (relaxed - only need 2 components)
            (cache.get('has_jsp_compiled_class', False) and 
            cache.get('has_jsp_hardcoded_command', False)) or
            
            # Method 3: Compiled class + suspicious URL
            (cache.get('has_jsp_compiled_class', False) and 
            cache.get('has_jsp_suspicious_url_pattern', False)) or
            
            # Method 4: Legacy detection (keep for other JSP types)
            (cache['has_jsp_runtime_exec'] and cache['has_hardcoded_backdoor_cmd']) or
            (cache['has_jsp_runtime_exec'] and cache['has_hardcoded_c2']) or
            cache.get('has_jsp_exec_hardcoded_cmd', False)
        )
        features["behavior_jsp_hardcoded_backdoor"] = int(behavior_jsp_hardcoded_backdoor)

        # NEW: JSP HTTP backdoor (HttpClient to suspicious domain)
        behavior_jsp_http_backdoor = bool(
            cache['has_jsp_http_client'] and 
            (cache['has_hardcoded_c2'] or cache['has_jsp_http_external_suspicious'])
        )
        features["behavior_jsp_http_backdoor"] = int(behavior_jsp_http_backdoor)
        behavior_jscript_webshell = bool(
        cache['has_jscript_directive'] and
        has_input and
        (cache['has_jscript_eval_encoded'] or has_exec)
        )
        features["behavior_jscript_webshell"] = int(behavior_jscript_webshell)

        # .NET Memory Shell (File 1 type)
        dotnet_memory_score = 0.0
        if cache['has_dotnet_frombase64']:
            dotnet_memory_score += 1.0
        if cache['has_dotnet_aes_decrypt']:
            dotnet_memory_score += 2.0
        if cache['has_dotnet_assembly_load']:
            dotnet_memory_score += 2.5
        if cache['has_dotnet_memorystream']:
            dotnet_memory_score += 0.5
        if cache['has_dotnet_session_cache']:
            dotnet_memory_score += 1.0
        if cache['has_dotnet_createinstance']:
            dotnet_memory_score += 1.5

        features["dotnet_memory_shell_score"] = float(dotnet_memory_score)

        # Behavioral flag: Score >= 5.0 AND (WebService or ASMX file)
        is_webservice = cache['has_dotnet_webservice'] or filepath.lower().endswith('.asmx')
        behavior_dotnet_memory_shell = bool(
            dotnet_memory_score >= 5.0 and is_webservice
        )
        features["behavior_dotnet_memory_shell"] = int(behavior_dotnet_memory_shell)
        # FIXED: Stricter reverse shell detection
        behavior_reverse = bool(self.BEHAVIOR_REVERSE_SHELL.search(normalized_code))
        features["behavior_reverse_shell"] = int(behavior_reverse)
        
        behavior_exfil = bool(self.BEHAVIOR_DATA_EXFIL.search(normalized_code))
        features["behavior_data_exfiltration"] = int(behavior_exfil)
        
        behavior_rawbody = bool(self.BEHAVIOR_RAWBODY_BACKDOOR.search(normalized_code))
        features["behavior_rawbody_backdoor"] = int(behavior_rawbody)
        
        behavior_fileman = bool(self.BEHAVIOR_FILE_MANAGER.search(normalized_code))
        features["behavior_file_manager"] = int(behavior_fileman)
        
        behavior_upload_chmod = bool(self.BEHAVIOR_UPLOAD_CHMOD.search(normalized_code))
        features["behavior_upload_chmod"] = int(behavior_upload_chmod)
        
        behavior_filterinput_exec = bool(self.BEHAVIOR_FILTERINPUT_EXEC.search(normalized_code))
        features["behavior_filterinput_exec"] = int(behavior_filterinput_exec)
        
        behavior_sqlmap_uploader = bool(self.BEHAVIOR_SQLMAP_UPLOADER.search(normalized_code))
        features["behavior_sqlmap_uploader"] = int(behavior_sqlmap_uploader)
        
        behavior_arbitrary_upload_path = bool(self.BEHAVIOR_ARBITRARY_UPLOAD_PATH.search(normalized_code))
        features["behavior_arbitrary_upload_path"] = int(behavior_arbitrary_upload_path)
        
        features["behavior_assign_input_then_exec"] = int(features.get("has_assign_input_then_exec", 0))
        features["behavior_exec_comment_split"] = int(features.get("has_exec_comment_split", 0))
        
        # === INTENT ANALYSIS ===
        intent_webshell = (
            behavior_chain * 3.0 +
            behavior_password * 2.0 +
            behavior_cookie * 2.0 +
            behavior_cookie_hash_gate * 2.5 +
            behavior_aspx_process_shell * 2.5 +
            behavior_jsp_memory_shell * 3.0 +
            behavior_jsp_request_exec * 2.5 +
            behavior_jsp_hardcoded_backdoor * 3.5 +  # ← THÊM
            behavior_jsp_http_backdoor * 3.0 +        # ← THÊM
            behavior_jscript_webshell * 3.5 +
            behavior_dotnet_memory_shell * 3.5 +
            behavior_obfusc * 1.5 +
            behavior_rawbody * 1.5 +
            behavior_fileman * 2.0 +
            behavior_upload_chmod * 2.0 +
            behavior_aspx_file_manager * 2.0 +
            features["short_input_exec_distance"] * 1.0 +
            features["exec_path_regex"] * 2.5 +
            features.get("has_assign_input_then_call", 0) * 1.0
        ) / 44.5  # Adjusted denominator
        features["intent_webshell_score"] = intent_webshell
        
        intent_backdoor = (
            behavior_password * 2.0 +
            behavior_sql * 2.0 +
            features["has_md5_cookie_check"] * 1.5 +
            behavior_cookie * 1.0
        ) / 6.5
        features["intent_backdoor_score"] = intent_backdoor
        
        intent_c2 = (
            behavior_reverse * 2.5 +
            behavior_exfil * 2.0 +
            behavior_aspx_tunneling * 3.0 +
            behavior_jsp_http_tunneling * 2.5 +  # NEW
            (features["has_fsockopen"] or features["has_socket_create"]) * 1.0
        ) / 11.0 
        features["intent_c2_score"] = intent_c2
        
        intent_dropper = (
            features["has_file_write_ops"] * 2.0 +
            features["has_long_base64"] * 1.5 +
            behavior_obfusc * 1.0
        ) / 4.5
        features["intent_dropper_score"] = intent_dropper
        
        # NEW: ASPX privilege escalation intent
        intent_privilege_esc = (
            behavior_aspx_privilege_pipe * 3.0 +
            cache['has_aspx_winapi'] * 2.0 +
            cache['has_aspx_privilege_esc'] * 2.5
        ) / 7.5
        features["intent_privilege_escalation"] = intent_privilege_esc
        
        # === STEALTH ANALYSIS ===
        stealth_techniques = (
            int(behavior_obfusc) +
            int(features["has_decode_chain"]) +
            int(features["has_string_index_obfusc"]) +
            int(features["has_alphabet_builder"]) +
            int(features["has_variable_function_call"]) +
            int(features.get("has_superglobal_var_call", 0)) +
            int(features.get("has_assign_input_then_call", 0)) +
            int(features["has_reflection"]) +
            int(features["has_comment_obfusc"]) +
            int(features["has_bitwise_chr"])
        )
        features["stealth_technique_count"] = stealth_techniques
        features["stealth_score_enhanced"] = stealth_techniques / 10.0
        
        # === COMBINED THREAT SCORE ===
        threat_score = (
            intent_webshell * 3.0 +
            intent_backdoor * 2.5 +
            intent_c2 * 2.0 +
            intent_dropper * 1.5 +
            intent_privilege_esc * 2.0 +  # NEW
            features["stealth_score_enhanced"] * 1.0 +
            features["exec_path_regex"] * 1.0
        ) / 13.0
        features["overall_threat_score"] = threat_score
        
        # === EXECUTION PATH ANALYSIS ===
        direct_path = int(
            has_input and has_exec and
            features["input_exec_distance"] < 0.2 and
            not behavior_obfusc and
            not has_decode
        )
        features["exec_path_direct"] = direct_path
        
        decoded_path = int(
            has_input and has_decode and has_exec and
            (behavior_chain or features["has_decode_chain"])
        )
        features["exec_path_decoded"] = decoded_path
        
        hidden_path = int(
            has_input and (
                features["has_variable_function_call"] or
                features.get("has_superglobal_var_call", 0) or
                features.get("has_assign_input_then_call", 0) or
                features["has_reflection"] or
                features["has_invoke_pattern"]
            )
        )
        features["exec_path_hidden"] = hidden_path
        
        indirect_path = int(has_input and features["has_dynamic_exec"])
        features["exec_path_indirect"] = indirect_path
        
        regex_path = int(has_input and has_regex_exec)
        features["exec_path_regex"] = regex_path
        
        # === DATA FLOW SCORE ===
        data_flow_complexity = 0
        if has_input:
            if has_exec:
                data_flow_complexity = 1
            if has_decode:
                data_flow_complexity += 1
            if features["has_dynamic_exec"]:
                data_flow_complexity += 1
            if (features["has_variable_function_call"] or 
                features.get("has_superglobal_var_call", 0) or 
                features.get("has_assign_input_then_call", 0)):
                data_flow_complexity += 1
            if features["has_reflection"]:
                data_flow_complexity += 1
        features["data_flow_complexity"] = data_flow_complexity
        critical_signature_score = (
            features.get("behavior_input_decode_exec", 0) +
            features.get("behavior_password_backdoor", 0) +
            features.get("behavior_upload_chmod", 0) +
            features.get("has_assign_input_then_call", 0) +
            features.get("behavior_aspx_process_shell", 0) +
            features.get("behavior_aspx_privilege_pipe", 0) +
            features.get("behavior_aspx_file_manager", 0) +
            features.get("behavior_jsp_memory_shell", 0) +
            features.get("behavior_jsp_request_exec", 0) +
            features.get("behavior_jsp_hardcoded_backdoor", 0) +  # ← KIỂM TRA CÓ DÒNG NÀY
            features.get("behavior_jsp_http_backdoor", 0) +
            features.get("behavior_jscript_webshell", 0) +
            features.get("behavior_dotnet_memory_shell", 0)
        )
        features["critical_signature_score"] = float(critical_signature_score)

        # Strong signature score
        strong_signature_score = (
            features.get("behavior_cookie_hash_gate_dyn_call", 0) +
            features.get("behavior_aspx_tunneling", 0) +
            features.get("behavior_jsp_http_tunneling", 0) +
            features.get("has_superglobal_var_call", 0) +
            features.get("behavior_filterinput_exec", 0) +
            features.get("behavior_arbitrary_upload_path", 0) +
            features.get("behavior_cookie_exec", 0) +
            features.get("behavior_rawbody_backdoor", 0) +
            features.get("behavior_file_manager", 0)  # ← ĐÃ THÊM Ở FIX TRƯỚC
        )
        features["strong_signature_score"] = float(strong_signature_score)

        # Combined signature indicator (binary flag)
        features["has_any_critical_signature"] = int(critical_signature_score > 0)
        features["has_any_strong_signature"] = int(strong_signature_score > 0)
        features["has_multiple_signatures"] = int(
            (critical_signature_score + strong_signature_score) >= 2
        )

        # ASPX-specific signature score
        aspx_signature_score = (
            features.get("behavior_aspx_process_shell", 0) +
            features.get("behavior_aspx_privilege_pipe", 0) +
            features.get("behavior_aspx_file_manager", 0) +
            features.get("behavior_aspx_tunneling", 0) +
            features.get("behavior_jscript_webshell", 0) +
            features.get("behavior_dotnet_memory_shell", 0)
        )
        features["aspx_signature_score"] = float(aspx_signature_score)

        # JSP-specific signature score
        jsp_signature_score = (
            features.get("behavior_jsp_memory_shell", 0) +
            features.get("behavior_jsp_request_exec", 0) +
            features.get("behavior_jsp_http_tunneling", 0) +
            features.get("behavior_jsp_hardcoded_backdoor", 0) +  # ← THÊM
            features.get("behavior_jsp_http_backdoor", 0)         # ← THÊM
        )
        features["jsp_signature_score"] = float(jsp_signature_score)

        # Weighted total signature score (gives more weight to signatures vs stats)
        features["total_weighted_signature_score"] = (
            critical_signature_score * 3.0 +
            strong_signature_score * 2.0 +
            features["overall_threat_score"] * 1.5
        )
        
        # Clean non-finite numbers
        for k, v in list(features.items()):
            if k.startswith("_"):
                continue
            if not isinstance(v, (int, float, str)) or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
                if isinstance(v, str):
                    continue
                features[k] = 0.0
        
        return features
    
    def extract_features(self, filepath: str) -> Optional[Dict[str, float]]:
        """Extract features from file path"""
        if not os.path.isfile(filepath):
            return None
        code = self.safe_read(filepath)
        if code is None:
            return None
        return self.extract_features_from_code(code, filepath)