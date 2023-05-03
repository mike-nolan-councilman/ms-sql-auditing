-- Create and Enable Audit Policies
USE master 
CREATE SERVER AUDIT SQL_Audit_SI
TO APPLICATION_LOG 
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE) 
ALTER SERVER AUDIT SQL_Audit_SI
WITH (STATE = ON)

-- Audit potentially dangerous procedures and other database items from MASTER
-- Windows Log: Application
-- Events: 33205 
use master
CREATE DATABASE AUDIT SPECIFICATION [SQL_DB_Master_Audit_SI]
FOR SERVER AUDIT [SQL_Audit_SI]
-- Auditing for Stored Procedures and Extended Stored Procedures
ADD (EXECUTE ON OBJECT::[dbo].[xp_cmdshell] BY [dbo]),			            -- Used to execute commands in the context of the service running MS-SQL
ADD (EXECUTE ON OBJECT::[dbo].[sp_addextendedproc] BY [dbo]),		        -- Audit for new custom extended stored procedures
ADD (EXECUTE ON OBJECT::[dbo].[sp_execute_external_script] BY [dbo]), 	-- Audit for external scripts like R and Python
ADD (EXECUTE ON OBJECT::[dbo].[Sp_oacreate] BY [dbo]),			            -- Audit OLE Automation Procedure execution
ADD (EXECUTE ON OBJECT::[dbo].[xp_dirtree] BY [dbo]),                   -- Used to steal hashes over SMB
ADD (EXECUTE ON OBJECT::[dbo].[xp_availablemedia] BY [dbo]),            -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_enumgroups] BY [dbo]),		            -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_fixeddrives] BY [dbo]),		            -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_servicecontrol] BY [dbo]),		        -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_subdirs] BY [dbo]),		                -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regaddmultistring] BY [dbo]),		      -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regdeletekey] BY [dbo]),		          -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regdeletevalue] BY [dbo]),		        -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regremovemultistring] BY [dbo]),		  -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regwrite] BY [dbo]),		              -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[xp_regread] BY [dbo]),		                -- CIS Benchmark for SQL Server 2008R2 and SQL Server 2012 
ADD (EXECUTE ON OBJECT::[dbo].[sp_addsrvrolemember] BY [dbo]),		      -- Can be used by an attacker to add a newly created account to privileged groups
ADD (EXECUTE ON OBJECT::[dbo].[sp_configure] BY [dbo]),		              -- Can be used by an attacker to enable other XPs such as xp_cmdshell for further use
ADD (EXECUTE ON OBJECT::[dbo].[sp_linkedservers] BY [dbo]),		          -- Can be used by an attacker to enable other XPs such as xp_cmdshell for further use
ADD (EXECUTE ON OBJECT::[dbo].[sp_helprotect] BY [dbo]),		            -- Can be used by an attacker to check privs on other SP and XPs for further use
ADD (EXECUTE ON OBJECT::[dbo].[sp_add_trusted_assembly] BY [dbo]),      -- Can be used by an attacker to add an untrusted DLL file for execution by a custom stored procedure
-- Auditing for certain queries an attacker may run
ADD (SELECT ON OBJECT::[sys].[sysdatabases] BY [dbo]),                  -- Can be used by an attacker to enumerate all the databases on a server
ADD (SELECT ON OBJECT::[sys].[servers] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[sysservers] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[server_audits] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[server_principals] BY [dbo]),             -- Can be used by an attacker to enumerate all the server principals on a server
ADD (SELECT ON OBJECT::[sys].[server_permissions] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[database_principals] BY [dbo]),           -- Can be used by an attacker to enumerate all the database principals on a server
ADD (SELECT ON OBJECT::[sys].[sql_logins] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[configurations] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[sysobjects] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[sysusers] BY [dbo]),
ADD (SELECT ON OBJECT::[sys].[sysprocesses] BY [dbo]),                  -- Can be used by an attacker to see which processes are running on a database server
-- Audit other items an attack may enumerate
ADD (SELECT ON OBJECT::[INFORMATION_SCHEMA].[TABLES] BY [dbo])
WITH (STATE = ON)

-- Audit server related activities
-- Windows Log: Application
-- Events: 33205 
CREATE SERVER AUDIT SPECIFICATION [SQL_Server_Audit_SI]
FOR SERVER AUDIT [SQL_Audit_SI]
-- Auditing for adding local accountss with high privileges
ADD (SERVER_PRINCIPAL_CHANGE_GROUP),                                    -- Used to log changes to server principals
ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),                           -- Used to log use of impersonation of database principals
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),                             -- Used to log use of impersonation of server principals
-- The below Action group names are related to GRANT being issued
ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_PERMISSION_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
ADD (FAILED_LOGIN_GROUP)
WITH (STATE = ON)


-- Audit potentially dangerous procedures and other database items from MSDB
-- Windows Log: Application
-- Events: 33205 
use msdb
CREATE DATABASE AUDIT SPECIFICATION [SQL_DB_MSDB_Audit_SI]
FOR SERVER AUDIT [SQL_Audit_SI]
-- Auditing for Stored Procedures and Extended Stored Procedures
ADD (EXECUTE ON OBJECT::[dbo].[sp_add_job] BY [dbo]),   	            -- Can be used by an attacker to add a job which can execute custom commands
ADD (EXECUTE ON OBJECT::[dbo].[sp_delete_job] BY [dbo]),    	        -- Can be used by an attacker to remove a job to hide what they have executed
-- Auditing for certain queries an attacker may run
ADD (SELECT ON OBJECT::[dbo].[sysjobs] BY [dbo])                      -- Can be used by an attacker to enumerate all jobs on a database server which may contain hardcoded credentials
WITH (STATE = ON)
