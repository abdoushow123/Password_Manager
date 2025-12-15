# Password Manager - Technical Implementation

## Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Security Implementation](#security-implementation)
4. [Core Components](#core-components)
5. [Data Structures](#data-structures)
6. [Encryption Scheme](#encryption-scheme)
7. [UI Implementation](#ui-implementation)
8. [Build System](#build-system)
9. [Memory Management](#memory-management)
10. [Thread Safety](#thread-safety)
11. [Error Handling](#error-handling)
12. [Performance Considerations](#performance-considerations)

## Project Overview
A secure, cross-platform password manager implemented in C with a GTK3-based graphical user interface. The application provides robust encryption for storing sensitive credentials while maintaining an intuitive user experience. The implementation follows secure coding practices and leverages industry-standard cryptographic libraries for maximum security.

### Key Technical Features
- **Secure Storage**: All credentials are encrypted using AES-256-GCM before being written to disk
- **Memory Protection**: Sensitive data is kept in protected memory regions and wiped when no longer needed
- **Defense in Depth**: Multiple layers of security including process isolation and secure memory handling
- **Audit Trail**: Comprehensive logging of security-critical operations
- **Secure Defaults**: Strong encryption settings and secure configuration out-of-the-box

## System Architecture

### High-Level Architecture
```
+-------------------+     +------------------+     +------------------+
|     GUI Layer     |<--->|  Business Logic  |<--->|  Data Storage   |
|  (GTK3, Windows)  |     |  (Manager.c/h)   |     |  (Encrypted)    |
+-------------------+     +------------------+     +------------------+
        ^                                                      |
        |                                                      v
        |                                            +------------------+
        +------------------------------------------|  Authentication  |
                                                   |   (auth.c/h)     |
                                                   +------------------+
```

### Detailed Component Breakdown

#### 1. GUI Layer (gui.c)
- **Window Management**:
  - Login/Registration dialogs
  - Main application window with tabbed interface
  - Modal dialogs for password entry/editing
  - System tray integration for background operation

- **UI Components**:
  - Secure password fields with visibility toggle
  - Searchable, sortable password list
  - Context menus for quick actions
  - Status bar with security indicators

- **Event Handlers**:
  - Button click handlers
  - Clipboard management
  - Auto-lock timer

#### 2. Business Logic (Manager.c/h)
- **Core Operations**:
  - Password entry CRUD operations
  - Search and filtering
  - Import/export functionality from Save files
  - Data validation

- **Security Controls**:
  - Session management
  - Clipboard clearing
  - Secure memory handling
  - Input sanitization

#### 3. Authentication (auth.c/h)
- **Authentication Flow**:
  - Master password verification
  - Session token generation
  - Failed attempt tracking
  - Account lockout mechanism

- **Key Management**:
  - Secure key derivation
  - Key storage in protected memory
  - Key rotation policies
  - Secure key destruction

#### 4. Data Storage
- **File Structure**:
  - Encrypted password database
  - Configuration files
  - Log files
  - Backup files

- **Encryption Layer**:
  - AES-256-GCM implementation
  - Secure key storage
  - Data integrity verification
  - Secure file operations

### Data Flow
1. **Initialization**:
   - Application starts and loads configuration
   - UI components are initialized
   - Security subsystems are initialized

2. **Authentication**:
   - User provides master password
   - System verifies password and derives encryption key
   - Session is established

3. **Operation**:
   - User interacts with the application
   - Business logic processes requests
   - Data is encrypted/decrypted as needed
   - UI is updated to reflect changes

4. **Shutdown**:
   - Sensitive data is wiped from memory
   - Session is terminated
   - Resources are released

### Component Interaction
1. **GUI Layer**: Handles all user interactions and rendering
2. **Business Logic**: Manages password entries and application state
3. **Authentication**: Verifies user identity and manages session security
4. **Data Storage**: Handles secure persistence of encrypted credentials

## Security Implementation

### Master Password Protection
- **PBKDF2 Key Derivation**:
  - Uses HMAC-SHA256 as the pseudorandom function
  - Configurable iteration count (default: 100,000 iterations)
  - 128-bit cryptographic salt for each password
  - Outputs a 256-bit encryption key

- **Secure Password Verification**:
  - Constant-time comparison to prevent timing attacks
  - Secure memory handling with `OPENSSL_cleanse`
  - Zeroization of sensitive data after use

- **Account Protection**:
  - Progressive delay between login attempts
  - Account lockout after 5 failed attempts
  - Secure session management

### Data Encryption
- **AES-256-GCM Implementation**:
  - 256-bit encryption keys
  - 96-bit random nonce for each encryption operation
  - 128-bit authentication tags for data integrity
  - Authenticated encryption with associated data (AEAD)

- **HMAC File Protection**:
  - HMAC-SHA256 for file integrity and authenticity
  - 256-bit HMAC keys derived from master password
  - Protects against file tampering and corruption
  - Constant-time comparison to prevent timing attacks
  - HMAC covers nonce, authentication tag, and ciphertext
  - Verification failure prevents loading of potentially compromised data

- **Key Management**:
  - Master key derived from user password
  - Session-based key caching
  - Secure key destruction after use

## Core Components

### 1. Authentication System (`auth.c/h`)
```c
// Core authentication functions
bool init_master_password(const char *password);
bool verify_master_password(const char *password);
int get_encryption_key(const char *password, unsigned char *key_out);
```
- **Features**:
  - Secure password hashing with PBKDF2
  - Password strength validation
  - Secure storage of password verification data
  - Account lockout mechanism

### 2. Password Management (`Manager.c/h`)
```c
// Core password management functions
List create_empty_list();
void add_entry(List *l, Password_Storing data);
void delete_entry(List *l, const char *service);
Password_Storing* find_entry(List l, const char *service);
```
- **Features**:
  - Linked list implementation for dynamic storage
  - Efficient search and retrieval operations
  - Secure memory management
  - Thread-safe operations

### 3. Cryptographic Operations (`Encryption.c/h`)
```c
// Core cryptographic functions
int derive_key_pbkdf2(const char *password, const unsigned char *salt, unsigned char *key_out);
int generate_salt(unsigned char *salt_out);
int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key,
                   unsigned char **ciphertext, size_t *ciphertext_len,
                   unsigned char *nonce_out, unsigned char *tag_out);
```
- **Features**:
  - AES-256-GCM encryption/decryption
  - Secure random number generation
  - PBKDF2 key derivation
  - Memory-safe operations

### 4. User Interface (`gui.c`)
- **Components**:
  - Login/Registration dialogs
  - Main application window
  - Password entry management interface
  - System tray integration

- **Features**:
  - Responsive GTK3 interface
  - Secure password fields
  - Clipboard management with auto-clear
  - Inactivity-based auto-lock

## Data Structures

### Password Entry
```c
#define SERVICE_MAX 50
#define USERNAME_MAX 50
#define MAIL_MAX 100
#define PASSWORD_MAX 50

typedef struct {
    char Service[SERVICE_MAX];      // Service/website name
    char Username[USERNAME_MAX];    // Username or email
    char Mail[MAIL_MAX];           // Associated email
    char Password[PASSWORD_MAX];    // Encrypted password
} Password_Storing;
```

### Linked List Implementation
```c
typedef struct cell {
    Password_Storing data;  // Password entry data
    struct cell *next;      // Pointer to next node
} Cell, *List;              // List type definition
```

## Encryption Scheme

### Master Key Derivation
1. **Input Processing**:
   - User enters master password
   - System generates cryptographically secure random salt
   - Password is normalized (UTF-8 encoding)

2. **Key Derivation**:
   - PBKDF2 with HMAC-SHA256
   - 100,000 iterations (configurable)
   - 256-bit output key

3. **Key Storage**:
   - Salt stored alongside verification data
   - Key never stored persistently
   - Session-based key caching with secure cleanup

### Data Encryption Process
1. **For each password entry**:
   - Generate 96-bit random nonce
   - Encrypt plaintext using AES-256-GCM
   - Store ciphertext, nonce, and authentication tag
   - Securely wipe plaintext from memory

2. **Decryption Process**:
   - Retrieve ciphertext, nonce, and tag
   - Verify authentication tag
   - Decrypt using AES-256-GCM
   - Return plaintext to secured memory

## UI Implementation

### Login Window
- **Components**:
  - Master password entry (hidden input)
  - New user registration option
  - Status indicators

- **Features**:
  - Secure password field
  - Account lockout notification
  - Session management

### Main Application Window
- **Components**:
  - Password list view
  - Entry management controls
  - Search functionality
  - Settings panel

- **Features**:
  - Sortable password list
  - Secure copy-to-clipboard
  - Auto-lock countdown
  - Password strength indicators

## Build System

### Dependencies
- **GTK3**: GUI toolkit
- **OpenSSL**: Cryptographic functions
- **GLib**: Utility functions
- **MinGW-w64**: Windows compilation

### Build Process
1. **Environment Setup**:
   ```bash
   # Install MSYS2 environment
   # Add to PATH:
   # - C:\msys64\mingw64\bin
   # - C:\msys64\usr\bin
   ```

2. **Install Dependencies**:
   ```bash
   pacman -S mingw-w64-x86_64-gtk3 \
              mingw-w64-x86_64-openssl \
              mingw-w64-x86_64-toolchain
   ```

3. **Build Commands**:
   ```bash
   # Using Makefile
   make clean
   make
   
   # Manual build
   gcc -o password_manager.exe \
       gui.c auth.c Encryption.c Manager.c logging.c \
       $(pkg-config --cflags --libs gtk+-3.0) \
       -lssl -lcrypto -lole32 -luser32 -lgdi32 -mwindows
   ```

## Memory Management

### Secure Memory Handling
- Use of `OPENSSL_cleanse` for sensitive data
- Zeroization of buffers after use
- Defensive memory allocation
- Protection against buffer overflows

### Resource Cleanup
- Proper cleanup of GTK resources
- Secure memory deallocation
- File handle management
- Network resource cleanup

## Thread Safety

### Thread-Safe Components
- Password encryption/decryption
- File I/O operations
- Clipboard management
- UI event handling

### Synchronization
- Mutex locks for shared resources
- Atomic operations where applicable
- Thread-local storage for sensitive data
- Deadlock prevention

## Error Handling

### Error Types
- Memory allocation failures
- I/O errors
- Cryptographic operation failures
- User input validation

### Recovery Mechanisms
- Graceful degradation
- Secure error reporting
- State rollback
- User notification system

## Performance Considerations

### Optimization Techniques
- Efficient data structures
- Memory pooling
- Lazy loading of resources
- Background processing

### Resource Usage
- Memory footprint analysis
- CPU utilization
- Disk I/O optimization
- Network efficiency
