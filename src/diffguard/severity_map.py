"""Deterministic CWE-to-severity mapping for consistent finding classification.

The LLM identifies vulnerabilities and CWE IDs; this module assigns severity
deterministically based on the CWE. This eliminates LLM non-determinism in
severity classification — the same CWE always gets the same severity.

For unmapped CWEs, the LLM's suggested severity is used as a fallback.

Sources: MITRE CWE Top 25 (2024/2025), OWASP Top 10 (2021/2025), SANS Top 25,
CWE-1003 Simplified Mapping, SAST tool coverage (SonarQube, Semgrep, CodeQL,
Checkmarx, Fortify, GitLab SAST, Mend SAST).
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from diffguard.llm.response import ConfidenceLevel, SeverityLevel

if TYPE_CHECKING:
    from diffguard.llm.response import Finding

__all__ = [
    "CWE_SEVERITY_MAP",
    "apply_severity_map",
    "map_severity",
]

# Deterministic mapping of CWE IDs to severity levels.
# For CWEs not in this map, the LLM's suggestion is used as fallback.
CWE_SEVERITY_MAP: dict[str, SeverityLevel] = {
    # ════════════════════════════════════════════════════════════════════
    # CRITICAL — Unauthenticated RCE, command/code injection, complete
    #            authentication bypass, memory corruption leading to
    #            arbitrary code execution
    # ════════════════════════════════════════════════════════════════════
    "CWE-77": SeverityLevel.CRITICAL,  # Command Injection (general)
    "CWE-78": SeverityLevel.CRITICAL,  # OS Command Injection
    "CWE-94": SeverityLevel.CRITICAL,  # Code Injection
    "CWE-95": SeverityLevel.CRITICAL,  # Eval Injection
    "CWE-96": SeverityLevel.CRITICAL,  # Static Code Injection
    "CWE-97": SeverityLevel.CRITICAL,  # Server-Side Includes (SSI) Injection
    "CWE-98": SeverityLevel.CRITICAL,  # PHP Remote File Inclusion
    "CWE-114": SeverityLevel.CRITICAL,  # Process Control
    "CWE-119": SeverityLevel.CRITICAL,  # Buffer Overflow (generic)
    "CWE-120": SeverityLevel.CRITICAL,  # Classic Buffer Overflow
    "CWE-121": SeverityLevel.CRITICAL,  # Stack-based Buffer Overflow
    "CWE-122": SeverityLevel.CRITICAL,  # Heap-based Buffer Overflow
    "CWE-287": SeverityLevel.CRITICAL,  # Improper Authentication (complete bypass)
    "CWE-288": SeverityLevel.CRITICAL,  # Auth Bypass via Alternate Path/Channel
    "CWE-290": SeverityLevel.CRITICAL,  # Auth Bypass by Spoofing
    "CWE-294": SeverityLevel.CRITICAL,  # Auth Bypass by Capture-Replay
    "CWE-302": SeverityLevel.CRITICAL,  # Auth Bypass by Assumed-Immutable Data
    "CWE-306": SeverityLevel.CRITICAL,  # Missing Auth for Critical Function
    "CWE-416": SeverityLevel.CRITICAL,  # Use After Free
    "CWE-426": SeverityLevel.CRITICAL,  # Untrusted Search Path
    "CWE-427": SeverityLevel.CRITICAL,  # Uncontrolled Search Path Element
    "CWE-470": SeverityLevel.CRITICAL,  # Unsafe Reflection
    "CWE-494": SeverityLevel.CRITICAL,  # Download of Code Without Integrity Check
    "CWE-787": SeverityLevel.CRITICAL,  # Out-of-bounds Write
    "CWE-829": SeverityLevel.CRITICAL,  # Inclusion of Untrusted Functionality
    "CWE-913": SeverityLevel.CRITICAL,  # Improper Control of Dynamic Code Resources
    "CWE-917": SeverityLevel.CRITICAL,  # Expression Language Injection
    "CWE-1336": SeverityLevel.CRITICAL,  # Template Engine Injection (SSTI)
    # ════════════════════════════════════════════════════════════════════
    # HIGH — SQL/XSS/path traversal/SSRF/XXE injection, deserialization,
    #        hardcoded credentials, broken crypto, missing authorization,
    #        unrestricted file upload, memory safety issues
    # ════════════════════════════════════════════════════════════════════
    "CWE-20": SeverityLevel.HIGH,  # Improper Input Validation
    "CWE-22": SeverityLevel.HIGH,  # Path Traversal
    "CWE-23": SeverityLevel.HIGH,  # Relative Path Traversal
    "CWE-35": SeverityLevel.HIGH,  # Path Traversal: '.../...//'
    "CWE-36": SeverityLevel.HIGH,  # Absolute Path Traversal
    "CWE-59": SeverityLevel.HIGH,  # Link Following
    "CWE-73": SeverityLevel.HIGH,  # External Control of File Name or Path
    "CWE-74": SeverityLevel.HIGH,  # Injection (generic)
    "CWE-79": SeverityLevel.HIGH,  # Cross-Site Scripting (XSS)
    "CWE-80": SeverityLevel.HIGH,  # Basic XSS
    "CWE-83": SeverityLevel.HIGH,  # XSS in Attributes
    "CWE-87": SeverityLevel.HIGH,  # Alternate XSS Syntax
    "CWE-88": SeverityLevel.HIGH,  # Argument Injection
    "CWE-89": SeverityLevel.HIGH,  # SQL Injection
    "CWE-90": SeverityLevel.HIGH,  # LDAP Injection
    "CWE-91": SeverityLevel.HIGH,  # XML Injection (Blind XPath)
    "CWE-93": SeverityLevel.HIGH,  # CRLF Injection
    "CWE-99": SeverityLevel.HIGH,  # Resource Injection
    "CWE-113": SeverityLevel.HIGH,  # HTTP Response Splitting
    "CWE-125": SeverityLevel.HIGH,  # Out-of-bounds Read
    "CWE-131": SeverityLevel.HIGH,  # Incorrect Calculation of Buffer Size
    "CWE-134": SeverityLevel.HIGH,  # Format String Vulnerability
    "CWE-138": SeverityLevel.HIGH,  # Improper Neutralization of Special Elements
    "CWE-184": SeverityLevel.HIGH,  # Incomplete List of Disallowed Inputs
    "CWE-190": SeverityLevel.HIGH,  # Integer Overflow or Wraparound
    "CWE-191": SeverityLevel.HIGH,  # Integer Underflow
    "CWE-212": SeverityLevel.HIGH,  # Improper Removal of Sensitive Info Before Storage
    "CWE-219": SeverityLevel.HIGH,  # Sensitive Data Under Web Root
    "CWE-242": SeverityLevel.HIGH,  # Use of Inherently Dangerous Function
    "CWE-250": SeverityLevel.HIGH,  # Execution with Unnecessary Privileges
    "CWE-256": SeverityLevel.HIGH,  # Plaintext Storage of Password
    "CWE-257": SeverityLevel.HIGH,  # Storing Passwords in Recoverable Format
    "CWE-259": SeverityLevel.HIGH,  # Hardcoded Password
    "CWE-260": SeverityLevel.HIGH,  # Password in Configuration File
    "CWE-266": SeverityLevel.HIGH,  # Incorrect Privilege Assignment
    "CWE-269": SeverityLevel.HIGH,  # Improper Privilege Management
    "CWE-276": SeverityLevel.HIGH,  # Incorrect Default Permissions
    "CWE-284": SeverityLevel.HIGH,  # Improper Access Control
    "CWE-285": SeverityLevel.HIGH,  # Improper Authorization
    "CWE-295": SeverityLevel.HIGH,  # Improper Certificate Validation
    "CWE-297": SeverityLevel.HIGH,  # Certificate Host Mismatch
    "CWE-304": SeverityLevel.HIGH,  # Missing Critical Step in Authentication
    "CWE-307": SeverityLevel.HIGH,  # Excessive Auth Attempts Not Restricted
    "CWE-311": SeverityLevel.HIGH,  # Missing Encryption of Sensitive Data
    "CWE-312": SeverityLevel.HIGH,  # Cleartext Storage of Sensitive Information
    "CWE-319": SeverityLevel.HIGH,  # Cleartext Transmission of Sensitive Info
    "CWE-321": SeverityLevel.HIGH,  # Hardcoded Cryptographic Key
    "CWE-325": SeverityLevel.HIGH,  # Missing Cryptographic Step
    "CWE-327": SeverityLevel.HIGH,  # Broken Cryptographic Algorithm
    "CWE-328": SeverityLevel.HIGH,  # Use of Weak Hash
    "CWE-345": SeverityLevel.HIGH,  # Insufficient Verification of Data Authenticity
    "CWE-347": SeverityLevel.HIGH,  # Improper Verification of Crypto Signature
    "CWE-415": SeverityLevel.HIGH,  # Double Free
    "CWE-428": SeverityLevel.HIGH,  # Unquoted Search Path or Element
    "CWE-434": SeverityLevel.HIGH,  # Unrestricted File Upload
    "CWE-476": SeverityLevel.HIGH,  # NULL Pointer Dereference
    "CWE-502": SeverityLevel.HIGH,  # Deserialization of Untrusted Data
    "CWE-522": SeverityLevel.HIGH,  # Insufficiently Protected Credentials
    "CWE-523": SeverityLevel.HIGH,  # Unprotected Transport of Credentials
    "CWE-538": SeverityLevel.HIGH,  # Sensitive Info in Externally-Accessible File
    "CWE-540": SeverityLevel.HIGH,  # Sensitive Information in Source Code
    "CWE-547": SeverityLevel.HIGH,  # Hardcoded Security-Relevant Constants
    "CWE-552": SeverityLevel.HIGH,  # Files Accessible to External Parties
    "CWE-564": SeverityLevel.HIGH,  # SQL Injection: Hibernate
    "CWE-599": SeverityLevel.HIGH,  # Missing Validation of OpenSSL Certificate
    "CWE-610": SeverityLevel.HIGH,  # Externally Controlled Reference to Resource
    "CWE-611": SeverityLevel.HIGH,  # XML External Entity (XXE)
    "CWE-643": SeverityLevel.HIGH,  # XPath Injection
    "CWE-652": SeverityLevel.HIGH,  # XQuery Injection
    "CWE-669": SeverityLevel.HIGH,  # Incorrect Resource Transfer Between Spheres
    "CWE-676": SeverityLevel.HIGH,  # Use of Potentially Dangerous Function
    "CWE-681": SeverityLevel.HIGH,  # Incorrect Conversion between Numeric Types
    "CWE-704": SeverityLevel.HIGH,  # Incorrect Type Conversion or Cast
    "CWE-732": SeverityLevel.HIGH,  # Incorrect Permission Assignment
    "CWE-749": SeverityLevel.HIGH,  # Exposed Dangerous Method or Function
    "CWE-759": SeverityLevel.HIGH,  # One-Way Hash Without a Salt
    "CWE-760": SeverityLevel.HIGH,  # One-Way Hash With Predictable Salt
    "CWE-762": SeverityLevel.HIGH,  # Mismatched Memory Management Routines
    "CWE-763": SeverityLevel.HIGH,  # Release of Invalid Pointer or Reference
    "CWE-776": SeverityLevel.HIGH,  # XML Entity Expansion
    "CWE-780": SeverityLevel.HIGH,  # Use of RSA Without OAEP
    "CWE-789": SeverityLevel.HIGH,  # Memory Allocation with Excessive Size
    "CWE-798": SeverityLevel.HIGH,  # Hardcoded Credentials
    "CWE-805": SeverityLevel.HIGH,  # Buffer Access with Incorrect Length
    "CWE-824": SeverityLevel.HIGH,  # Access of Uninitialized Pointer
    "CWE-825": SeverityLevel.HIGH,  # Expired Pointer Dereference
    "CWE-843": SeverityLevel.HIGH,  # Type Confusion
    "CWE-862": SeverityLevel.HIGH,  # Missing Authorization
    "CWE-863": SeverityLevel.HIGH,  # Incorrect Authorization
    "CWE-915": SeverityLevel.HIGH,  # Mass Assignment
    "CWE-916": SeverityLevel.HIGH,  # Password Hash with Insufficient Effort
    "CWE-918": SeverityLevel.HIGH,  # Server-Side Request Forgery (SSRF)
    "CWE-943": SeverityLevel.HIGH,  # NoSQL Injection
    "CWE-1321": SeverityLevel.HIGH,  # Prototype Pollution
    "CWE-1390": SeverityLevel.HIGH,  # Weak Authentication
    # ════════════════════════════════════════════════════════════════════
    # MEDIUM — CSRF, information disclosure, open redirect, cookie/session
    #          issues, race conditions, resource consumption, weak
    #          randomness, error handling, integrity checks, HTTP issues
    # ════════════════════════════════════════════════════════════════════
    "CWE-116": SeverityLevel.MEDIUM,  # Improper Encoding or Escaping of Output
    "CWE-117": SeverityLevel.MEDIUM,  # Log Injection
    "CWE-129": SeverityLevel.MEDIUM,  # Improper Validation of Array Index
    "CWE-178": SeverityLevel.MEDIUM,  # Improper Handling of Case Sensitivity
    "CWE-193": SeverityLevel.MEDIUM,  # Off-by-one Error
    "CWE-200": SeverityLevel.MEDIUM,  # Information Exposure
    "CWE-201": SeverityLevel.MEDIUM,  # Insertion of Sensitive Info Into Sent Data
    "CWE-203": SeverityLevel.MEDIUM,  # Observable Discrepancy (Side Channel)
    "CWE-208": SeverityLevel.MEDIUM,  # Observable Timing Discrepancy
    "CWE-252": SeverityLevel.MEDIUM,  # Unchecked Return Value
    "CWE-253": SeverityLevel.MEDIUM,  # Incorrect Check of Function Return Value
    "CWE-271": SeverityLevel.MEDIUM,  # Privilege Dropping/Lowering Errors
    "CWE-272": SeverityLevel.MEDIUM,  # Least Privilege Violation
    "CWE-280": SeverityLevel.MEDIUM,  # Improper Handling of Insufficient Permissions
    "CWE-296": SeverityLevel.MEDIUM,  # Improper Following of Certificate Chain of Trust
    "CWE-300": SeverityLevel.MEDIUM,  # Channel Accessible by Non-Endpoint
    "CWE-313": SeverityLevel.MEDIUM,  # Cleartext Storage in File or on Disk
    "CWE-315": SeverityLevel.MEDIUM,  # Cleartext Storage of Sensitive Info in Cookie
    "CWE-316": SeverityLevel.MEDIUM,  # Cleartext Storage of Sensitive Info in Memory
    "CWE-322": SeverityLevel.MEDIUM,  # Key Exchange Without Entity Authentication
    "CWE-323": SeverityLevel.MEDIUM,  # Reusing a Nonce/Key Pair in Encryption
    "CWE-324": SeverityLevel.MEDIUM,  # Use of Key Past Expiration Date
    "CWE-326": SeverityLevel.MEDIUM,  # Inadequate Encryption Strength
    "CWE-329": SeverityLevel.MEDIUM,  # Generation of Predictable IV with CBC Mode
    "CWE-330": SeverityLevel.MEDIUM,  # Use of Insufficiently Random Values
    "CWE-331": SeverityLevel.MEDIUM,  # Insufficient Entropy
    "CWE-335": SeverityLevel.MEDIUM,  # Incorrect Usage of Seeds in PRNG
    "CWE-336": SeverityLevel.MEDIUM,  # Same Seed in PRNG
    "CWE-337": SeverityLevel.MEDIUM,  # Predictable Seed in PRNG
    "CWE-338": SeverityLevel.MEDIUM,  # Cryptographically Weak PRNG
    "CWE-340": SeverityLevel.MEDIUM,  # Predictable Numbers or Identifiers
    "CWE-346": SeverityLevel.MEDIUM,  # Origin Validation Error
    "CWE-348": SeverityLevel.MEDIUM,  # Use of Less Trusted Source
    "CWE-352": SeverityLevel.MEDIUM,  # Cross-Site Request Forgery (CSRF)
    "CWE-353": SeverityLevel.MEDIUM,  # Missing Support for Integrity Check
    "CWE-354": SeverityLevel.MEDIUM,  # Improper Validation of Integrity Check Value
    "CWE-358": SeverityLevel.MEDIUM,  # Improperly Implemented Security Check
    "CWE-359": SeverityLevel.MEDIUM,  # Exposure of Private Personal Information
    "CWE-362": SeverityLevel.MEDIUM,  # Race Condition
    "CWE-367": SeverityLevel.MEDIUM,  # TOCTOU Race Condition
    "CWE-369": SeverityLevel.MEDIUM,  # Divide By Zero
    "CWE-377": SeverityLevel.MEDIUM,  # Insecure Temporary File
    "CWE-379": SeverityLevel.MEDIUM,  # Temp File in Dir with Insecure Permissions
    "CWE-384": SeverityLevel.MEDIUM,  # Session Fixation
    "CWE-400": SeverityLevel.MEDIUM,  # Uncontrolled Resource Consumption
    "CWE-401": SeverityLevel.MEDIUM,  # Missing Release of Memory
    "CWE-402": SeverityLevel.MEDIUM,  # Transmission of Private Resources into New Sphere
    "CWE-404": SeverityLevel.MEDIUM,  # Improper Resource Shutdown or Release
    "CWE-407": SeverityLevel.MEDIUM,  # Inefficient Algorithmic Complexity
    "CWE-409": SeverityLevel.MEDIUM,  # Improper Handling of Compressed Data (Zip Bomb)
    "CWE-413": SeverityLevel.MEDIUM,  # Improper Resource Locking
    "CWE-419": SeverityLevel.MEDIUM,  # Unprotected Primary Channel
    "CWE-425": SeverityLevel.MEDIUM,  # Forced Browsing
    "CWE-436": SeverityLevel.MEDIUM,  # Interpretation Conflict
    "CWE-441": SeverityLevel.MEDIUM,  # Confused Deputy
    "CWE-444": SeverityLevel.MEDIUM,  # HTTP Request/Response Smuggling
    "CWE-457": SeverityLevel.MEDIUM,  # Use of Uninitialized Variable
    "CWE-459": SeverityLevel.MEDIUM,  # Incomplete Cleanup
    "CWE-471": SeverityLevel.MEDIUM,  # Modification of Assumed-Immutable Data
    "CWE-472": SeverityLevel.MEDIUM,  # External Control of Assumed-Immutable Web Param
    "CWE-497": SeverityLevel.MEDIUM,  # Exposure of Sensitive System Information
    "CWE-501": SeverityLevel.MEDIUM,  # Trust Boundary Violation
    "CWE-521": SeverityLevel.MEDIUM,  # Weak Password Requirements
    "CWE-526": SeverityLevel.MEDIUM,  # Sensitive Info in Environment Variable
    "CWE-530": SeverityLevel.MEDIUM,  # Exposure of Backup File
    "CWE-532": SeverityLevel.MEDIUM,  # Sensitive Data in Log Files
    "CWE-548": SeverityLevel.MEDIUM,  # Information Through Directory Listing
    "CWE-565": SeverityLevel.MEDIUM,  # Reliance on Cookies Without Validation
    "CWE-566": SeverityLevel.MEDIUM,  # Auth Bypass via User-Controlled SQL PK
    "CWE-598": SeverityLevel.MEDIUM,  # GET Request With Sensitive Query Strings
    "CWE-601": SeverityLevel.MEDIUM,  # Open Redirect
    "CWE-613": SeverityLevel.MEDIUM,  # Insufficient Session Expiration
    "CWE-614": SeverityLevel.MEDIUM,  # Missing Secure Flag on Cookie
    "CWE-620": SeverityLevel.MEDIUM,  # Unverified Password Change
    "CWE-639": SeverityLevel.MEDIUM,  # Insecure Direct Object Reference (IDOR)
    "CWE-640": SeverityLevel.MEDIUM,  # Weak Password Recovery Mechanism
    "CWE-644": SeverityLevel.MEDIUM,  # HTTP Headers for Scripting Syntax
    "CWE-651": SeverityLevel.MEDIUM,  # Exposure of WSDL Containing Sensitive Info
    "CWE-662": SeverityLevel.MEDIUM,  # Improper Synchronization
    "CWE-665": SeverityLevel.MEDIUM,  # Improper Initialization
    "CWE-667": SeverityLevel.MEDIUM,  # Improper Locking
    "CWE-668": SeverityLevel.MEDIUM,  # Exposure of Resource to Wrong Sphere
    "CWE-670": SeverityLevel.MEDIUM,  # Always-Incorrect Control Flow
    "CWE-672": SeverityLevel.MEDIUM,  # Operation on Resource After Expiration
    "CWE-674": SeverityLevel.MEDIUM,  # Uncontrolled Recursion
    "CWE-682": SeverityLevel.MEDIUM,  # Incorrect Calculation
    "CWE-697": SeverityLevel.MEDIUM,  # Incorrect Comparison
    "CWE-706": SeverityLevel.MEDIUM,  # Use of Incorrectly-Resolved Name or Reference
    "CWE-757": SeverityLevel.MEDIUM,  # Algorithm Downgrade
    "CWE-764": SeverityLevel.MEDIUM,  # Multiple Locks of Critical Resource
    "CWE-770": SeverityLevel.MEDIUM,  # Allocation Without Limits or Throttling
    "CWE-772": SeverityLevel.MEDIUM,  # Missing Release of Resource
    "CWE-775": SeverityLevel.MEDIUM,  # Missing Release of File Descriptor
    "CWE-784": SeverityLevel.MEDIUM,  # Cookies in Security Decision Without Validation
    "CWE-821": SeverityLevel.MEDIUM,  # Incorrect Synchronization
    "CWE-833": SeverityLevel.MEDIUM,  # Deadlock
    "CWE-838": SeverityLevel.MEDIUM,  # Inappropriate Encoding for Output Context
    "CWE-908": SeverityLevel.MEDIUM,  # Use of Uninitialized Resource
    "CWE-909": SeverityLevel.MEDIUM,  # Missing Initialization of Resource
    "CWE-922": SeverityLevel.MEDIUM,  # Insecure Storage of Sensitive Information
    "CWE-924": SeverityLevel.MEDIUM,  # Improper Enforcement of Message Integrity
    "CWE-940": SeverityLevel.MEDIUM,  # Improper Verification of Source of Channel
    "CWE-941": SeverityLevel.MEDIUM,  # Incorrectly Specified Destination in Channel
    "CWE-942": SeverityLevel.MEDIUM,  # Permissive Cross-domain Policy
    "CWE-1004": SeverityLevel.MEDIUM,  # Missing HttpOnly Flag on Cookie
    "CWE-1021": SeverityLevel.MEDIUM,  # Clickjacking
    "CWE-1188": SeverityLevel.MEDIUM,  # Initialization with Insecure Default
    "CWE-1204": SeverityLevel.MEDIUM,  # Generation of Weak IV
    "CWE-1216": SeverityLevel.MEDIUM,  # Lockout Mechanism Errors
    "CWE-1275": SeverityLevel.MEDIUM,  # Sensitive Cookie with Improper SameSite
    "CWE-1284": SeverityLevel.MEDIUM,  # Improper Validation of Specified Quantity in Input
    "CWE-1327": SeverityLevel.MEDIUM,  # Binding to Unrestricted IP Address
    "CWE-1333": SeverityLevel.MEDIUM,  # ReDoS
    "CWE-1419": SeverityLevel.MEDIUM,  # Incorrect Initialization of Resource
    # ════════════════════════════════════════════════════════════════════
    # LOW — Verbose error messages, minor information leaks, deprecated
    #       function usage, configuration issues, minor coding flaws
    # ════════════════════════════════════════════════════════════════════
    "CWE-2": SeverityLevel.LOW,  # Environment Issues
    "CWE-11": SeverityLevel.LOW,  # ASP.NET Misconfiguration: Debug Binary
    "CWE-13": SeverityLevel.LOW,  # ASP.NET Misconfiguration: Password in Config
    "CWE-15": SeverityLevel.LOW,  # External Control of System/Config Setting
    "CWE-16": SeverityLevel.LOW,  # Configuration
    "CWE-75": SeverityLevel.LOW,  # Failure to Sanitize Special Elements
    "CWE-76": SeverityLevel.LOW,  # Improper Neutralization of Equivalent Elements
    "CWE-155": SeverityLevel.LOW,  # Improper Neutralization of Wildcards
    "CWE-180": SeverityLevel.LOW,  # Validate Before Canonicalize
    "CWE-182": SeverityLevel.LOW,  # Collapse of Data into Unsafe Value
    "CWE-183": SeverityLevel.LOW,  # Permissive List of Allowed Inputs
    "CWE-185": SeverityLevel.LOW,  # Incorrect Regular Expression
    "CWE-209": SeverityLevel.LOW,  # Error Message Information Exposure
    "CWE-235": SeverityLevel.LOW,  # Improper Handling of Extra Parameters
    "CWE-243": SeverityLevel.LOW,  # chroot Jail Without Changing Working Dir
    "CWE-244": SeverityLevel.LOW,  # Improper Clearing of Heap Memory
    "CWE-430": SeverityLevel.LOW,  # Deployment of Wrong Handler
    "CWE-466": SeverityLevel.LOW,  # Return of Pointer Value Outside Range
    "CWE-467": SeverityLevel.LOW,  # Use of sizeof() on Pointer Type
    "CWE-469": SeverityLevel.LOW,  # Use of Pointer Subtraction to Determine Size
    "CWE-477": SeverityLevel.LOW,  # Use of Obsolete Function
    "CWE-489": SeverityLevel.LOW,  # Active Debug Code
    "CWE-520": SeverityLevel.LOW,  # .NET Misconfiguration: Use of Impersonation
    "CWE-537": SeverityLevel.LOW,  # Runtime Error Message with Sensitive Info
    "CWE-541": SeverityLevel.LOW,  # Sensitive Information in Include File
    "CWE-554": SeverityLevel.LOW,  # ASP.NET: Not Using Input Validation Framework
    "CWE-562": SeverityLevel.LOW,  # Return of Stack Variable Address
    "CWE-573": SeverityLevel.LOW,  # Improper Following of Specification by Caller
    "CWE-587": SeverityLevel.LOW,  # Assignment of Fixed Address to Pointer
    "CWE-588": SeverityLevel.LOW,  # Attempt to Access Child of Non-structure Pointer
    "CWE-606": SeverityLevel.LOW,  # Unchecked Input for Loop Condition
    "CWE-617": SeverityLevel.LOW,  # Reachable Assertion
    "CWE-684": SeverityLevel.LOW,  # Incorrect Provision of Specified Functionality
    "CWE-685": SeverityLevel.LOW,  # Wrong Number of Function Arguments
    "CWE-686": SeverityLevel.LOW,  # Incorrect Argument Type
    "CWE-687": SeverityLevel.LOW,  # Incorrectly Specified Argument Value
    "CWE-754": SeverityLevel.LOW,  # Improper Check for Exceptional Conditions
    "CWE-756": SeverityLevel.LOW,  # Missing Custom Error Page
    "CWE-758": SeverityLevel.LOW,  # Reliance on Undefined Behavior
    "CWE-1024": SeverityLevel.LOW,  # Comparison of Incompatible Types
    "CWE-1077": SeverityLevel.LOW,  # Floating Point Comparison with Wrong Operator
    "CWE-1174": SeverityLevel.LOW,  # ASP.NET: Improper Model Validation
    "CWE-1236": SeverityLevel.LOW,  # Formula Injection (CSV)
    "CWE-1335": SeverityLevel.LOW,  # Incorrect Bitwise Shift of Integer
    "CWE-1341": SeverityLevel.LOW,  # Multiple Releases of Same Resource
    # ════════════════════════════════════════════════════════════════════
    # INFO — Code quality, best practices, defense-in-depth, logging
    # ════════════════════════════════════════════════════════════════════
    "CWE-223": SeverityLevel.INFO,  # Omission of Security-relevant Information
    "CWE-398": SeverityLevel.INFO,  # Code Quality Indicator
    "CWE-448": SeverityLevel.INFO,  # Excessive Use of Hard-coded Literals
    "CWE-561": SeverityLevel.INFO,  # Dead Code
    "CWE-563": SeverityLevel.INFO,  # Assignment to Variable Without Use
    "CWE-710": SeverityLevel.INFO,  # Improper Adherence to Coding Standards
    "CWE-778": SeverityLevel.INFO,  # Insufficient Logging
    "CWE-830": SeverityLevel.INFO,  # Inclusion of Web Functionality from Untrusted Source
    "CWE-1061": SeverityLevel.INFO,  # Insufficient Encapsulation
    "CWE-1078": SeverityLevel.INFO,  # Inappropriate Source Code Style
    "CWE-1104": SeverityLevel.INFO,  # Use of Unmaintained Third Party Components
    "CWE-1116": SeverityLevel.INFO,  # Inaccurate Comments
    "CWE-1164": SeverityLevel.INFO,  # Irrelevant Code
}

# Severity ordering for cap comparisons (lower index = more severe)
_SEVERITY_ORDER = [
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
]


def _severity_index(severity: SeverityLevel) -> int:
    """Return the index of a severity level (0=Critical, 4=Info)."""
    return _SEVERITY_ORDER.index(severity)


def _cap_severity(severity: SeverityLevel, cap: SeverityLevel) -> SeverityLevel:
    """Cap severity so it does not exceed the given limit."""
    if _severity_index(severity) < _severity_index(cap):
        return cap
    return severity


def map_severity(finding: Finding) -> SeverityLevel:
    """Determine the severity for a finding based on its CWE ID.

    Rules:
    1. Look up the CWE in the deterministic map.
    2. If not found, use the LLM's suggested severity.
    3. If confidence is Low, cap severity at Medium.

    Args:
        finding: The parsed finding from LLM response.

    Returns:
        The deterministic severity level.
    """
    cwe = finding.cwe_id
    severity = CWE_SEVERITY_MAP[cwe] if cwe and cwe in CWE_SEVERITY_MAP else finding.severity

    if finding.confidence == ConfidenceLevel.LOW:
        severity = _cap_severity(severity, SeverityLevel.MEDIUM)

    return severity


def apply_severity_map(findings: list[Finding]) -> list[Finding]:
    """Apply deterministic severity mapping to a list of findings.

    Args:
        findings: List of findings with LLM-assigned severity.

    Returns:
        New list of findings with deterministic severity.
    """
    return [replace(f, severity=map_severity(f)) for f in findings]
