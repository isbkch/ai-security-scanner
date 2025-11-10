# Database Integration Guide

This guide covers the database integration for the AI Security Scanner, including setup, usage, and schema documentation.

## Overview

The AI Security Scanner uses PostgreSQL to persist scan results, track vulnerabilities over time, analyze trends, and build a vulnerability knowledge base. The database integration is **optional** but highly recommended for production use.

## Features

### Core Capabilities

- **Scan History**: Complete record of all scans with metadata and statistics
- **Vulnerability Tracking**: Detailed vulnerability records with AI analysis results
- **Trend Analysis**: Compare scans to track security improvements over time
- **Pattern Analytics**: Track pattern effectiveness and accuracy
- **Cost Monitoring**: LLM API usage tracking and cost estimation

### Benefits

1. **Historical Context**: Understand how your codebase security evolves
2. **Trend Identification**: Spot recurring vulnerabilities and patterns
3. **Team Collaboration**: Share scan results across team members
4. **Audit Trail**: Maintain compliance with security audit requirements
5. **Cost Optimization**: Monitor and optimize AI API costs

## Quick Start

### 1. Database Setup

**Option A: Docker (Recommended)**

```bash
docker run -d \
  --name ai-scanner-db \
  -e POSTGRES_PASSWORD=scanner123 \
  -e POSTGRES_USER=scanner \
  -e POSTGRES_DB=ai_security_scanner \
  -p 5432:5432 \
  postgres:15
```

**Option B: Local PostgreSQL**

```bash
# Create database
createdb ai_security_scanner

# Create user (optional)
psql -c "CREATE USER scanner WITH PASSWORD 'scanner123';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE ai_security_scanner TO scanner;"
```

### 2. Configure Environment

Add database credentials to `.env`:

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ai_security_scanner
DB_USER=scanner
DB_PASSWORD=scanner123
```

### 3. Initialize Schema

```bash
# Initialize database tables
ai-security-scanner db init

# Test connection
ai-security-scanner db test-connection
```

You should see: `✓ Database connection successful!`

### 4. Run Your First Scan with Persistence

```bash
# Scan and save to database
ai-security-scanner scan /path/to/project --save-db

# View scan in history
ai-security-scanner db history
```

## Database Schema

### Tables Overview

The database consists of 5 main tables:

```
┌─────────────────────┐
│   scan_records      │  ← Main scan metadata
└──────────┬──────────┘
           │
           ├─────┐
           │     │
┌──────────▼──────────┐  ┌─────────────────────┐
│ vulnerability_      │  │ llm_usage_metrics   │
│    records          │  │                     │
└─────────────────────┘  └─────────────────────┘
           │
           │
┌──────────▼──────────┐  ┌─────────────────────┐
│ scan_comparisons    │  │  pattern_usage      │
└─────────────────────┘  └─────────────────────┘
```

### 1. scan_records

Stores metadata and statistics for each scan.

**Key Fields:**
- `scan_id` - Unique identifier for the scan
- `scan_timestamp` - When the scan was performed
- `target_path` - Path or repository scanned
- `files_scanned` - Number of files analyzed
- `total_vulnerabilities` - Total vulnerabilities found
- `severity counts` - Breakdown by severity (critical, high, medium, low)
- `ai_analysis_enabled` - Whether AI analysis was used
- `scanner_version` - Version of scanner used

**Example Query:**
```sql
SELECT scan_id, scan_timestamp, total_vulnerabilities, scan_duration
FROM scan_records
ORDER BY scan_timestamp DESC
LIMIT 10;
```

### 2. vulnerability_records

Stores individual vulnerability findings.

**Key Fields:**
- `vulnerability_type` - Type of vulnerability (SQL Injection, XSS, etc.)
- `severity` - Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- `confidence` - Confidence in finding (HIGH, MEDIUM, LOW)
- `file_path` - Path to vulnerable file
- `line_number` - Line where vulnerability was found
- `code_snippet` - Code context
- `cwe_id` - CWE classification
- `ai_analyzed` - Whether AI verified the finding
- `false_positive_probability` - AI-estimated false positive rate
- `status` - Current status (open, fixed, false_positive, ignored)

**Example Query:**
```sql
SELECT v.vulnerability_type, v.severity, v.file_path, v.line_number
FROM vulnerability_records v
JOIN scan_records s ON v.scan_id = s.id
WHERE s.scan_id = 'your-scan-id'
  AND v.severity = 'HIGH'
ORDER BY v.severity;
```

### 3. scan_comparisons

Tracks changes between scans for trend analysis.

**Key Fields:**
- `baseline_scan_id` - Reference scan
- `current_scan_id` - Comparison scan
- `new_vulnerabilities` - Newly introduced vulnerabilities
- `fixed_vulnerabilities` - Resolved vulnerabilities
- `persistent_vulnerabilities` - Still present
- `overall_trend` - improved, degraded, or stable

**Example Query:**
```sql
SELECT
  baseline_scan_id,
  current_scan_id,
  new_vulnerabilities,
  fixed_vulnerabilities,
  overall_trend
FROM scan_comparisons
WHERE overall_trend = 'degraded'
ORDER BY comparison_timestamp DESC;
```

### 4. pattern_usage

Tracks effectiveness of vulnerability detection patterns.

**Key Fields:**
- `pattern_name` - Name of the pattern
- `times_triggered` - How many times pattern matched
- `true_positives` - Confirmed vulnerabilities
- `false_positives` - False alarms
- `accuracy_rate` - Calculated accuracy

**Example Query:**
```sql
SELECT
  pattern_name,
  times_triggered,
  true_positives,
  false_positives,
  accuracy_rate
FROM pattern_usage
ORDER BY accuracy_rate DESC;
```

### 5. llm_usage_metrics

Tracks LLM API usage and costs.

**Key Fields:**
- `provider` - LLM provider (openai, anthropic)
- `model` - Model used
- `total_requests` - Number of API calls
- `prompt_tokens` - Tokens in prompts
- `completion_tokens` - Tokens in responses
- `estimated_cost` - Estimated cost in USD

**Example Query:**
```sql
SELECT
  provider,
  model,
  SUM(total_requests) as total_requests,
  SUM(estimated_cost) as total_cost
FROM llm_usage_metrics
GROUP BY provider, model;
```

## CLI Commands

### Database Management

```bash
# Initialize database schema
ai-security-scanner db init

# Test database connection
ai-security-scanner db test-connection

# View scan history (last 10 scans)
ai-security-scanner db history

# View more scans
ai-security-scanner db history -n 25

# Show detailed scan information
ai-security-scanner db show <scan-id>

# View aggregated statistics
ai-security-scanner db stats
```

### Scanning with Persistence

```bash
# Scan and save to database
ai-security-scanner scan /path/to/repo --save-db

# Scan with AI and save
ai-security-scanner scan /path/to/repo --save-db

# Scan specific language and save
ai-security-scanner scan /path/to/repo -l python --save-db
```

## Programmatic Usage

### Saving Scan Results

```python
from ai_security_scanner.core.scanner import SecurityScanner
from ai_security_scanner.database import (
    create_database_manager,
    ScanPersistenceService
)

# Run scan
scanner = SecurityScanner()
scan_result = scanner.scan_directory("/path/to/repo")

# Save to database
db_manager = create_database_manager()
service = ScanPersistenceService(db_manager)
success = service.save_scan_result(scan_result)

print(f"Scan {scan_result.scan_id} saved: {success}")
```

### Retrieving Scan History

```python
from ai_security_scanner.database import (
    create_database_manager,
    ScanPersistenceService
)

db_manager = create_database_manager()
service = ScanPersistenceService(db_manager)

# Get recent scans
recent_scans = service.get_recent_scans(limit=10)

for scan in recent_scans:
    print(f"{scan.scan_id}: {scan.total_vulnerabilities} vulnerabilities")
```

### Comparing Scans

```python
# Compare two scans
comparison = service.compare_scans(
    baseline_scan_id="scan-001",
    current_scan_id="scan-002"
)

print(f"New vulnerabilities: {comparison['new_vulnerabilities']}")
print(f"Fixed vulnerabilities: {comparison['fixed_vulnerabilities']}")
print(f"Trend: {comparison['overall_trend']}")
```

### Getting Statistics

```python
from datetime import datetime, timedelta

# Get statistics for last 30 days
start_date = datetime.now() - timedelta(days=30)
stats = service.get_scan_statistics(start_date=start_date)

print(f"Total scans: {stats['total_scans']}")
print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
print(f"Average per scan: {stats['avg_vulnerabilities_per_scan']:.2f}")
```

## Migrations with Alembic

### Creating Migrations

```bash
# Auto-generate migration from model changes
alembic revision --autogenerate -m "Add new column to vulnerabilities"

# Create empty migration
alembic revision -m "Custom migration"
```

### Applying Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Apply specific migration
alembic upgrade <revision_id>

# Rollback one migration
alembic downgrade -1

# Rollback to specific revision
alembic downgrade <revision_id>
```

### Migration History

```bash
# View migration history
alembic history

# View current version
alembic current

# View pending migrations
alembic show head
```

## Best Practices

### 1. Regular Backups

```bash
# Backup database
pg_dump ai_security_scanner > backup_$(date +%Y%m%d).sql

# Restore from backup
psql ai_security_scanner < backup_20250109.sql
```

### 2. Database Maintenance

```sql
-- Vacuum and analyze tables periodically
VACUUM ANALYZE scan_records;
VACUUM ANALYZE vulnerability_records;

-- Check database size
SELECT pg_size_pretty(pg_database_size('ai_security_scanner'));

-- Check table sizes
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### 3. Index Optimization

The schema includes indexes on:
- `scan_records.scan_id` (unique)
- `scan_records.scan_timestamp`
- `vulnerability_records.scan_id`
- `vulnerability_records.severity`
- `vulnerability_records.cwe_id`
- `vulnerability_records(severity, status)` (composite)

### 4. Retention Policies

Consider implementing data retention:

```sql
-- Delete scans older than 90 days
DELETE FROM scan_records
WHERE scan_timestamp < NOW() - INTERVAL '90 days';

-- Archive old scans instead
CREATE TABLE scan_records_archive AS
SELECT * FROM scan_records
WHERE scan_timestamp < NOW() - INTERVAL '90 days';

DELETE FROM scan_records
WHERE scan_timestamp < NOW() - INTERVAL '90 days';
```

## Troubleshooting

### Connection Issues

```bash
# Test connection
ai-security-scanner db test-connection

# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Check credentials
psql -h localhost -p 5432 -U scanner -d ai_security_scanner
```

### Migration Errors

```bash
# Check current migration state
alembic current

# Stamp database to specific revision
alembic stamp head

# Force upgrade
alembic upgrade head --sql > migration.sql
psql ai_security_scanner < migration.sql
```

### Performance Issues

```sql
-- Check slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Analyze query plan
EXPLAIN ANALYZE
SELECT * FROM vulnerability_records WHERE severity = 'HIGH';
```

## Security Considerations

### 1. Database Credentials

- Never commit `.env` file with real credentials
- Use environment variables for sensitive data
- Rotate database passwords regularly
- Use SSL/TLS for database connections in production

### 2. Access Control

```sql
-- Create read-only user for reporting
CREATE USER reporter WITH PASSWORD 'reporting_password';
GRANT CONNECT ON DATABASE ai_security_scanner TO reporter;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO reporter;

-- Revoke unnecessary privileges
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 3. SSL Connections

Update `.env` for SSL:

```bash
DB_SSL_MODE=require  # or 'verify-full' for strict verification
```

## Advanced Topics

### Custom Queries

Create custom views for common queries:

```sql
-- View: Recent high-severity vulnerabilities
CREATE VIEW recent_high_severity AS
SELECT
  s.scan_id,
  s.scan_timestamp,
  v.vulnerability_type,
  v.file_path,
  v.line_number
FROM vulnerability_records v
JOIN scan_records s ON v.scan_id = s.id
WHERE v.severity = 'HIGH'
  AND s.scan_timestamp > NOW() - INTERVAL '7 days'
ORDER BY s.scan_timestamp DESC;
```

### Integration with BI Tools

Export data for analysis:

```bash
# Export to CSV
psql -d ai_security_scanner -c "COPY (SELECT * FROM scan_records) TO STDOUT CSV HEADER" > scans.csv

# Export for Tableau/PowerBI
psql -d ai_security_scanner -c "SELECT * FROM scan_records" > scans.tsv
```

## Support

For issues with database integration:

1. Check [GitHub Issues](https://github.com/isbkch/ai-security-scanner/issues)
2. Review [CLAUDE.md](../CLAUDE.md) for developer guidance
3. Consult PostgreSQL documentation: https://www.postgresql.org/docs/

## References

- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [PostgreSQL Best Practices](https://www.postgresql.org/docs/current/tutorial.html)
- [Database Schema](../ai_security_scanner/database/models/scan_history.py)
