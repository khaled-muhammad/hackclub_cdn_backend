# HackClub CDN API Documentation

This document provides comprehensive documentation for the HackClub CDN REST API endpoints. This is a part of Hack Club CDN project (It is the backend of the project)

## Authentication

All API endpoints require authentication using JWT tokens stored in cookies. The system supports:

- **Slack OAuth integration** for user authentication
- **JWT tokens** stored in HTTP-only cookies
- **Automatic token refresh** mechanism

## Base URL Structure

All CDN endpoints are prefixed with `/api/cdn/`

## API Endpoints

### 📁 Folders API

#### List/Create Folders

```
GET /api/cdn/folders/
POST /api/cdn/folders/
```

**POST Body Example:**

```json
{
  "name": "My Folder",
  "parent": null  // or folder UUID
}
```

#### Folder Details

```
GET /api/cdn/folders/{id}/
PUT /api/cdn/folders/{id}/
PATCH /api/cdn/folders/{id}/
DELETE /api/cdn/folders/{id}/
```

#### Folder Contents

```
GET /api/cdn/folders/{id}/contents/
```

Returns both subfolders and files in the specified folder.

#### Root Folder

```
GET /api/cdn/folders/root/
```

Gets the root folder and its immediate contents.

---

### 📄 Files API

#### List Files

```
GET /api/cdn/files/
```

**Query Parameters:**

- `folder_id`: Filter by folder UUID
- `search`: Search in filenames
- `type`: Filter by type (`images`, `videos`, `documents`)
- `page`: Pagination page number
- `page_size`: Items per page (default: 20, max: 100)

#### Register Uploaded Files

```
POST /api/cdn/files/upload/
```

**JSON Body:**

```json
{
  "filename": "example.jpg",
  "original_filename": "IMG_001.jpg", 
  "cdn_url": "https://cdn.example.com/files/abc123.jpg",
  "file_size": 1048576,
  "mime_type": "image/jpeg",
  "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "folder_id": "uuid-here"
}
```

**Features:**

- ✅ Client-side CDN upload workflow
- ✅ Duplicate detection using provided hashes
- ✅ File metadata registration
- ✅ Automatic thumbnail generation queue
- ✅ Activity logging

#### File Details

```
GET /api/cdn/files/{id}/
PUT /api/cdn/files/{id}/
PATCH /api/cdn/files/{id}/
DELETE /api/cdn/files/{id}/
```

#### Get Download URL

```
GET /api/cdn/files/{id}/download/
```

**Response:**

```json
{
  "download_url": "https://cdn.example.com/files/abc123.jpg",
  "filename": "example.jpg",
  "size": 1048576,
  "mime_type": "image/jpeg"
}
```

#### Star/Unstar File

```
POST /api/cdn/files/{id}/star/
```

#### Starred Files

```
GET /api/cdn/files/starred/
```

#### Recent Files

```
GET /api/cdn/files/recent/
```

---

### 🔗 Sharing API

#### List/Create Shares

```
GET /api/cdn/shares/
POST /api/cdn/shares/
```

**POST Body Example:**

```json
{
  "resource_type": "file",  // or "folder"
  "resource_id": "uuid-here",
  "permission_level": "view",  // "view", "download", "edit", "admin"
  "is_public": true,
  "expires_at": "2024-12-31T23:59:59Z",
  "allow_download": true,
  "download_limit": 100
}
```

#### Share Details

```
GET /api/cdn/shares/{id}/
PUT /api/cdn/shares/{id}/
DELETE /api/cdn/shares/{id}/
```

#### Public Share Access

```
GET /api/cdn/shares/public/?token=your-public-token
```

---

### 📊 Activity & Analytics

#### Activity Log

```
GET /api/cdn/activity/
```

Returns user's activity history with pagination.

#### File Analytics

```
GET /api/cdn/analytics/
```

Returns analytics data for user's files.

#### Processing Jobs

```
GET /api/cdn/processing/
```

Returns status of background processing jobs (thumbnails, etc.).

---

### 🗑️ Trash Management

#### List Trash Items

```
GET /api/cdn/trash/
```

#### Restore from Trash

```
POST /api/cdn/trash/{id}/restore/
```

#### Empty Trash

```
POST /api/cdn/trash/empty/
```

---

### 📈 Dashboard & Search

#### Dashboard Stats

```
GET /api/cdn/dashboard/
```

**Response Example:**

```json
{
  "stats": {
    "total_files": 150,
    "total_folders": 25,
    "total_size": 1073741824,
    "total_size_human": "1.0 GB"
  },
  "recent_activity": [...],
  "recent_files": [...],
  "storage_by_type": [...]
}
```

#### Global Search

```
GET /api/cdn/search/?q=search-term
```

---

### 🔗 External Upload Service

#### Upload to 0x0.st

```
POST /api/cdn/upload-0x0/
```

**Form Data:**

- `file`: The file to upload

**Description:**
This endpoint acts as a proxy to upload files directly to https://0x0.st using **HTTPX** for superior large file handling. The file is uploaded with streaming support, proper connection pooling, and the User-Agent "FriendlyUploader". The response from 0x0.st is returned directly to the client.

**Large File Optimizations:**

- Uses HTTPX instead of requests (better for >10MB files)
- Streaming upload prevents memory issues
- Smart timeout scaling based on file size
- Connection pooling for better performance

**Features:**

- ✅ Direct proxy to 0x0.st
- ✅ **HTTPX-powered** - Superior large file handling vs requests
- ✅ **Streaming uploads** - Memory efficient for large files
- ✅ Activity logging with retry tracking
- ✅ Smart timeout handling (120s base + 30s per MB)
- ✅ Automatic retry mechanism (3 attempts)
- ✅ File size limit (200MB)
- ✅ **Connection pooling** and limits optimization
- ✅ Enhanced error handling with specific timeout types
- ✅ Preserves original response format

**Example Usage:**

```bash
curl -H "Authorization: Bearer your-jwt-token" \
     -F "file=@reddy.png" \
     http://localhost:8000/api/cdn/upload-0x0/
```

**Error Responses:**

- `400` - No file provided
- `413` - File too large (>200MB)
- `503` - Connection error (service unavailable)
- `504` - Upload timeout (after 3 retry attempts)
- `502` - Other upload failures

---

## Data Models

### File Model Fields

- `id`: UUID primary key
- `filename`: Current filename
- `original_filename`: Original uploaded filename
- `folder`: Foreign key to folder
- `owner`: Foreign key to user profile
- `file_size`: Size in bytes
- `mime_type`: MIME type
- `file_extension`: File extension
- `storage_path`: Path in storage system
- `cdn_url`: CDN URL if available
- `thumbnail_url`: Thumbnail URL
- `preview_url`: Preview URL
- `is_processed`: Processing status
- `processing_status`: Current processing state
- `created_at`: Upload timestamp
- `last_accessed`: Last access timestamp

### Folder Model Fields

- `id`: UUID primary key
- `name`: Folder name
- `parent`: Foreign key to parent folder
- `owner`: Foreign key to user profile
- `path`: Full folder path
- `is_root`: Whether this is root folder
- `created_at`: Creation timestamp

### Share Model Fields

- `id`: UUID primary key
- `resource_type`: "file" or "folder"
- `resource_id`: UUID of shared resource
- `owner`: Share creator
- `shared_with_user`: Target user (optional for public shares)
- `permission_level`: Access level
- `is_public`: Public share flag
- `public_token`: Public access token
- `expires_at`: Expiration timestamp
- `download_limit`: Maximum downloads
- `download_count`: Current download count

## Error Responses

The API returns standard HTTP status codes:

- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `409`: Conflict (e.g., duplicate file)
- `500`: Internal Server Error

**Error Response Format:**

```json
{
  "error": "Error message",
  "details": {...}
}
```

## Authentication Endpoints

### Slack OAuth Callback

```
GET /api/slack/callback?code=oauth-code
```

### Retrieve Authentication

```
POST /api/auth/retrieve
Body: {"auth_code": "short-lived-token"}
```

### Get Current User

```
GET /api/auth/me
```

### Refresh Token

```
POST /api/auth/refresh
```

### Update Password

```
POST /api/auth/reset_password
Body: {"new_password": "...", "old_password": "..."}
```

## Features Implemented

✅ **File Management**

- Client-side CDN upload workflow (files uploaded directly to CDN)
- File metadata registration with duplicate detection
- Folder organization
- CDN file access and download URLs
- File versioning support

✅ **Sharing & Permissions**

- Public and private sharing
- Permission levels (view, download, edit, admin)
- Expiring shares
- Download limits

✅ **Search & Discovery**

- Global search across files and folders
- File type filtering
- Recent files
- Starred items

✅ **Analytics & Monitoring**

- Activity logging
- File access analytics
- Processing job status
- Storage usage stats

✅ **Trash Management**

- Soft delete with trash
- Restore functionality
- Auto-cleanup after 30 days

✅ **Authentication**

- Slack OAuth integration
- JWT token management
- Cookie-based auth for web clients

✅ **External Services**

- Proxy upload to 0x0.st with custom User-Agent
- Direct response passthrough
- Activity logging for external uploads

## Next Steps

To get started:

1. **Install dependencies:** `pip install -r requirements.txt` (now includes HTTPX for better large file handling)
2. **Run migrations:** `python manage.py makemigrations && python manage.py migrate`
3. **Create superuser:** `python manage.py createsuperuser`
4. **Start server:** `python manage.py runserver`
5. **Access API at:** `http://localhost:8000/api/cdn/`

The API is now fully functional and ready for frontend integration!
