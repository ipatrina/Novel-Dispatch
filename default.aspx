<% @Page Language="C#" Debug="false" ResponseEncoding="utf-8" %>
<% @Import Namespace="System" %>
<% @Import Namespace="System.Collections.Generic" %>
<% @Import Namespace="System.IO" %>
<% @Import Namespace="System.IO.Compression" %>
<% @Import Namespace="System.Net" %>
<% @Import Namespace="System.Security" %>
<% @Import Namespace="System.Security.Cryptography" %>
<% @Import Namespace="System.Text" %>
<% @Import Namespace="System.Web" %>
<% @Import Namespace="System.Web.Security" %>
<% @Import Namespace="System.Web.UI" %>
<% @Import Namespace="System.Web.UI.WebControls" %>


<Script runat=server>

    // Novel Dispatch
    // Version: 7.1.1
    // Date: 2022.11

    // Configuration file
    string I_Config = @"C:\ProgramData\Novel Dispatch\config.txt";

    // Debug settings
    bool I_Debug = false;

    void Page_Load(object sender, EventArgs e)
    {
        try
        {
            // Load server configuration file
            LoadConfig();
            SetLanguage();

            // Web crawler detection
            if (!VerifyRequest()) { WriteLog("[REFUSED] Web crawlers blocked."); SetResponse(403); return; }

            // Load request query
            LoadParameter(ParseQueryString(Request.Url.Query));

            // Logout request
            if (R_Action.ToLower().StartsWith("q")) { Response.StatusCode = 401; Response.Headers.Add("Clear-Site-Data", "*"); return; }

            // API access
            if (!string.IsNullOrEmpty(R_APIKey)) { if (VerifyAPI()) { SetAPIResponse(); } else { WriteLog("[REFUSED] " + Request.Url.Query.Substring(1)); SetResponse(403); } return; }

            // Authorization
            if (!string.IsNullOrEmpty(R_Token)) { string X_Token = DecryptToken(R_Token); if (X_Token.Length > 0) { R_Authorized = true; LoadParameter(ParseQueryString(X_Token)); } }
            else if (!string.IsNullOrEmpty(R_Signature)) { R_Authorized = VerifySignature(); }
            else if (!string.IsNullOrEmpty(R_File)) { R_Authorized = false; }
            else if (VerifyBasicAuth()) { R_Authorized = true; }
            else if (!string.IsNullOrEmpty(GetParameter("Anonymous-Group"))) { SetGroup(GetParameter("Anonymous-Group")); if (!string.IsNullOrEmpty(X_Group)) { R_Authorized = true; } }
            if ((!string.IsNullOrEmpty(R_Expire) && Convert.ToInt64(R_Expire) < Time()) || (!string.IsNullOrEmpty(R_Host) && !VerifyUserHost(R_Host))) { R_Authorized = false; }
            if (!R_Authorized)
            {
                if (string.IsNullOrEmpty(R_Directory) && string.IsNullOrEmpty(R_File) && string.IsNullOrEmpty(R_Signature) && string.IsNullOrEmpty(R_Token)) { SetResponse(401); }
                else { WriteLog("[REFUSED] " + Request.Url.Query.Substring(1)); SetResponse(403); } return;
            }

            // Parse directory
            R_Directory = PathRegulation(R_Directory); R_File = PathRegulation(R_File); R_Write = PathRegulation(R_Write);
            SetRecursive(); if (VerifyRecursive() < 0) { SetResponse(403); return; }
            LoadPath();

            // File delete procedure
            if (!string.IsNullOrEmpty(R_Remove))
            {
                if (X_Permission.Contains("x") && VerifyBucketAccess(R_Bucket) && !string.IsNullOrEmpty(R_Absolute) && !R_Remove.Contains("*") && !R_Remove.Contains("\\") && !R_Remove.Substring(1).Contains("/") && R_Remove != "/." && !R_Remove.Contains("/.."))
                {
                    string R_Remove_Log = "(" + X_Group + ") ";
                    if (!R_Remove.StartsWith("/"))
                    {
                        string G_Remove_File = R_Absolute + "\\" + R_Remove;
                        if (File.Exists(G_Remove_File)) { File.Delete(G_Remove_File); WriteLog(R_Remove_Log + "[REMOVE] " + G_Remove_File); }
                    }
                    else
                    {
                        string G_Remove_Directory = R_Absolute + "\\" + R_Remove.Substring(1);
                        if (Directory.Exists(G_Remove_Directory)) { Directory.Delete(G_Remove_Directory, true); WriteLog(R_Remove_Log + "[REMOVE] " + G_Remove_Directory); }
                    }
                    SetResponse(204);
                }
                else
                {
                    SetResponse(403);
                }
                return;
            }

            // File download procedure
            if (!string.IsNullOrEmpty(R_File) && !string.IsNullOrEmpty(R_Absolute))
            {
                string G_Path = R_Absolute + "\\" + R_File;
                FileInfo G_Info = new System.IO.FileInfo(G_Path);
                long G_Size = G_Info.Length;
                long G_Start = 0;
                long G_End = G_Size - 1;

                string R_Range = GetRequestHeader("Range");
                bool G_Range = false;
                if (!string.IsNullOrEmpty(R_Range))
                {
                    string[] G_Bytes = R_Range.Split('=')[1].Split('-');
                    if (string.IsNullOrEmpty(G_Bytes[0])) { if (!string.IsNullOrEmpty(G_Bytes[1])) { G_Start = G_End - Convert.ToInt64(G_Bytes[1]); G_Range = true; } }
                    else { G_Start = Convert.ToInt64(G_Bytes[0]); if (!string.IsNullOrEmpty(G_Bytes[1])) { if (Convert.ToInt64(G_Bytes[1]) <= Convert.ToInt64(G_End)) { G_End = Convert.ToInt64(G_Bytes[1]); } } G_Range = true; }
                }
                if (!G_Range) { Response.StatusCode = 200; } else { Response.StatusCode = 206; }
                long G_Length = G_End - G_Start + 1;

                string G_Content_Disposition = "inline"; if (G_Info.Extension.ToLower() == ".apk") { G_Content_Disposition = "attachment"; }
                Response.AddHeader("Accept-Ranges", "bytes");
                Response.AddHeader("Connection", "keep-alive");
                Response.AddHeader("Content-Disposition", G_Content_Disposition + "; filename=" + HttpUtility.UrlEncode(G_Info.Name).Replace("+", "%20"));
                Response.AddHeader("Content-Length", G_Length.ToString());
                if (G_Range) { Response.AddHeader("Content-Range", "bytes " + G_Start.ToString() + "-" + G_End.ToString() + "/" + G_Size.ToString()); }
                Response.ContentType = GetMimeType(G_Info.Extension);
                Response.AddHeader("ETag", "\"" + SHA1(HttpUtility.UrlEncode(G_Info.Name)) + "\"");

                WriteLog(R_Directory + "\\" + R_File + " (" + G_Start.ToString() + "-" + G_End.ToString() + "/" + G_Size.ToString() + ")");

                Response.TransmitFile(G_Path, G_Start, G_Length);
                Response.Flush();
                return;
            }

            // File upload procedure
            if (R_Action.ToLower().StartsWith("c")) { R_Action = "Write"; X_Write_Cancel = true; }
            if ((X_Write || R_Action.ToLower().StartsWith("w")) && X_Permission.Contains("w") && VerifyBucketAccess(R_Bucket) && !string.IsNullOrEmpty(R_Absolute))
            {
                try
                {
                    string S_Write_Magic = "<?NDSP.W";
                    long S_Write_Block_Size = 1048576;
                    long S_Write_Block_Count = 128;
                    long S_Write_Info_Size = 1024;

                    string G_Absolute = R_Absolute;
                    if (!string.IsNullOrEmpty(R_Write)) { G_Absolute += "\\" + R_Write; }
                    if (!Directory.Exists(G_Absolute)) { Directory.CreateDirectory(G_Absolute); }

                    string G_Content_Range = GetRequestHeader("Content-Range");
                    if (!string.IsNullOrEmpty(G_Content_Range))
                    {
                        string G_Filename = GetRequestHeader("Content-Disposition");
                        if (G_Filename.Contains(";")) { G_Filename = G_Filename.Substring(G_Filename.IndexOf(';') + 1).Trim(); } else { G_Filename = ""; }
                        if (G_Filename.Contains("=")) { G_Filename = HttpUtility.UrlDecode(G_Filename.Substring(G_Filename.IndexOf('=') + 1).Trim()); } else { G_Filename = ""; }
                        if (string.IsNullOrEmpty(G_Filename)) { SetResponse(400); return; } if (G_Filename.ToLower().EndsWith(".tmp")) { SetResponse(403); return; }
                        G_Absolute += "\\" + G_Filename; if (File.Exists(G_Absolute)) { SetResponse(409); return; }
                        string G_Write_Binary = G_Absolute + ".dat.tmp";
                        string G_Write_Info = G_Absolute + ".bin.tmp";

                        long G_Content_Length = Request.ContentLength;
                        long G_Content_Range_Start = 0;
                        long G_Content_Range_End = 0;
                        long G_Content_Range_Size = 0;
                        long G_Content_Range_Length = 0;

                        if (G_Content_Range.Contains(" ")) { G_Content_Range = G_Content_Range.Substring(G_Content_Range.IndexOf(' ') + 1).Trim(); }
                        if (G_Content_Range.Contains("/")) { G_Content_Range_Length = GetLong(G_Content_Range.Substring(G_Content_Range.IndexOf('/') + 1).Trim()); G_Content_Range = G_Content_Range.Substring(0, G_Content_Range.IndexOf('/')).Trim(); } else { G_Content_Range = ""; }
                        if (G_Content_Range.Contains("-")) { G_Content_Range_Start = GetLong(G_Content_Range.Substring(0, G_Content_Range.IndexOf('-')).Trim()); G_Content_Range_End = GetLong(G_Content_Range.Substring(G_Content_Range.IndexOf('-') + 1).Trim()); if (G_Content_Range_End == 0) { G_Content_Range_End = G_Content_Range_Length - 1; } } else { G_Content_Range = "*"; }
                        G_Content_Range_Size = G_Content_Range_End - G_Content_Range_Start + 1;
                        if (string.IsNullOrEmpty(G_Content_Range) || G_Content_Range_Size < 0) { SetResponse(416); return; }
                        if (G_Content_Range_Length <= 0) { SetResponse(400); return; }

                        long G_Write_Block_Size = S_Write_Block_Size;
                        if (!string.IsNullOrEmpty(GetParameter("Block-Size"))) { long.TryParse(GetParameter("Block-Size"), out G_Write_Block_Size); }
                        if (!string.IsNullOrEmpty(R_Block)) { long.TryParse(R_Block, out G_Write_Block_Size); }
                        if (G_Write_Block_Size >= 102400 && G_Write_Block_Size <= 104857600) { S_Write_Block_Size = G_Write_Block_Size; }

                        byte[] G_Bytes = new byte[0];
                        if (G_Content_Length > 0) { G_Bytes = StreamToBytes(Request.InputStream); }

                        X_Stream_Info = null;
                        int S_Write_Attempt = 10;
                        int G_Write_Attempt = 0;
                        while (G_Write_Attempt < S_Write_Attempt)
                        {
                            try { X_Stream_Info = new FileStream(G_Write_Info, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); break; }
                            catch { G_Write_Attempt += 1; System.Threading.Thread.Sleep(100); }
                        }
                        if (G_Write_Attempt >= S_Write_Attempt) { SetResponse(400); return; }
                        if (File.Exists(G_Absolute)) { CloseStream(); File.Delete(G_Write_Info); SetResponse(400); return; }

                        byte[] G_Buffer_Info = new byte[0];
                        byte[] G_Buffer_Info_Header = new byte[0];
                        long G_File_Length = 0;
                        long G_File_Offset = 0;
                        long G_Block_Size = 0;
                        long G_Block_Count = 0;
                        long G_Buffer_Block_Count = 0;
                        long G_Record_Offset = 0;
                        bool G_Write_Cancelled = false;
                        bool G_Load_Info = true;
                        while (G_Load_Info)
                        {
                            G_Load_Info = false;
                            X_Stream_Info.Seek(0, SeekOrigin.Begin);
                            G_Buffer_Info = new byte[8];
                            if (X_Stream_Info.Length >= S_Write_Info_Size) { X_Stream_Info.Read(G_Buffer_Info, 0, 8); }
                            if (S_Write_Magic != Encoding.UTF8.GetString(G_Buffer_Info))
                            {
                                X_Stream_Info.SetLength(S_Write_Info_Size);
                                G_Buffer_Info = new byte[S_Write_Info_Size];
                                Array.Copy(BitConverter.GetBytes(G_Content_Range_Length), 0, G_Buffer_Info, 8, 8);
                                Array.Copy(new byte[8], 0, G_Buffer_Info, 16, 8);
                                Array.Copy(BitConverter.GetBytes(S_Write_Block_Size), 0, G_Buffer_Info, 24, 8);
                                Array.Copy(BitConverter.GetBytes(S_Write_Block_Count), 0, G_Buffer_Info, 32, 8);
                                Array.Copy(BitConverter.GetBytes((long) 64), 0, G_Buffer_Info, 40, 8);
                                X_Stream_Info.Seek(0, SeekOrigin.Begin);
                                X_Stream_Info.Write(G_Buffer_Info, 0, G_Buffer_Info.Length);
                                if (G_Content_Range_Length >= 0) { WriteLog("(" + X_Group + ") " + "[CREATE] " + G_Absolute + " (" + FileSizeToString(G_Content_Range_Length) + ")"); }
                            }

                            G_Buffer_Info_Header = new byte[40];
                            X_Stream_Info.Seek(8, SeekOrigin.Begin);
                            X_Stream_Info.Read(G_Buffer_Info_Header, 0, 40);
                            G_File_Length = BitConverter.ToInt64(G_Buffer_Info_Header, 0);
                            G_File_Offset = BitConverter.ToInt64(G_Buffer_Info_Header, 8);
                            G_Block_Size = BitConverter.ToInt64(G_Buffer_Info_Header, 16);
                            G_Block_Count = BitConverter.ToInt64(G_Buffer_Info_Header, 24);
                            G_Buffer_Block_Count = ((G_File_Length - G_File_Offset) + (G_Block_Size - ((G_File_Length - G_File_Offset) % G_Block_Size))) / G_Block_Size; if (G_Block_Count > G_Buffer_Block_Count) { G_Block_Count = G_Buffer_Block_Count; }
                            G_Record_Offset = BitConverter.ToInt64(G_Buffer_Info_Header, 32);

                            if ((X_Write_Cancel || G_File_Length < 0) && !G_Write_Cancelled)
                            {
                                G_Write_Cancelled = true;
                                X_Stream_Info.Seek(8, SeekOrigin.Begin);
                                X_Stream_Info.Write(BitConverter.GetBytes((long) -1), 0, 8);
                                if (File.Exists(G_Write_Binary)) { File.Delete(G_Write_Binary); }
                                if (X_Write_Cancel || G_Content_Length > 0)
                                {
                                    CloseStream();
                                    SetResponse(204);
                                    return;
                                }
                                else
                                {
                                    X_Stream_Info.Seek(0, SeekOrigin.Begin);
                                    X_Stream_Info.Write(new byte[S_Write_Info_Size], 0, Convert.ToInt32(S_Write_Info_Size));
                                    G_Load_Info = true;
                                }
                            }
                        }

                        byte[] G_Buffer_Info_Block = new byte[G_Block_Count];
                        X_Stream_Info.Seek(G_Record_Offset, SeekOrigin.Begin);
                        X_Stream_Info.Read(G_Buffer_Info_Block, 0, Convert.ToInt32(G_Block_Count));

                        int G_Write_Response = 0;
                        if (G_Content_Range_Length != G_File_Length) { SetResponse(409); return; }
                        if (G_Content_Length > 0 && G_Write_Response == 0)
                        {
                            if (G_Content_Range_Start >= G_File_Offset && G_Content_Range_End < G_File_Offset + G_Block_Size * G_Block_Count && G_Content_Range_Start % G_Block_Size == 0 && ((G_Content_Range_Length - G_Content_Range_Start < G_Block_Size && G_Content_Range_End + 1 == G_Content_Range_Length) || (G_Content_Range_End + 1) % G_Block_Size == 0))
                            {
                                int G_Buffer_Index = Convert.ToInt32((G_Content_Range_Start - G_File_Offset) / G_Block_Size);
                                if (G_Buffer_Info_Block[G_Buffer_Index] != 0xFF)
                                {
                                    if (G_Content_Length != G_Content_Range_Size || G_Content_Length != G_Bytes.Length || (!string.IsNullOrEmpty(GetRequestHeader("X-SHA1")) && GetRequestHeader("X-SHA1").ToUpper().Trim() != SHA1_Bytes(G_Bytes))) { G_Write_Response = 400; }
                                    else
                                    {
                                        X_Stream_Binary = null;
                                        G_Write_Attempt = 0;
                                        while (G_Write_Attempt < S_Write_Attempt)
                                        {
                                            try { X_Stream_Binary = new FileStream(G_Write_Binary, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read); break; }
                                            catch { G_Write_Attempt += 1; System.Threading.Thread.Sleep(100); }
                                        }
                                        if (G_Write_Attempt >= S_Write_Attempt) { SetResponse(400); return; }
                                        if (File.Exists(G_Absolute)) { CloseStream(); File.Delete(G_Write_Binary); SetResponse(400); return; }
                                        if (G_Write_Binary.Length < G_Content_Range_Length) { X_Stream_Binary.SetLength(G_Content_Range_Length); }
                                        X_Stream_Binary.Seek(G_Content_Range_Start, SeekOrigin.Begin);
                                        X_Stream_Binary.Write(G_Bytes, 0, G_Bytes.Length);
                                        X_Stream_Binary.Close();
                                        X_Stream_Binary.Dispose();
                                        X_Stream_Binary = null;
                                        G_Buffer_Info_Block[G_Buffer_Index] = 0xFF;
                                        G_Write_Response = 202;
                                    }
                                }
                                else { G_Write_Response = 416; }
                            }
                            else { G_Write_Response = 416; }
                        }
                        else {
                            bool G_Block_Renew = true;
                            for (int G_Block_Byte_Offset = 0; G_Block_Byte_Offset < G_Buffer_Info_Block.Length; G_Block_Byte_Offset++)
                            {
                                if (G_Buffer_Info_Block[G_Block_Byte_Offset] == 0x00) { G_Block_Renew = false; break; }
                            }
                            if (G_Block_Renew) {
                                for (int G_Block_Byte_Offset = 0; G_Block_Byte_Offset < G_Buffer_Info_Block.Length; G_Block_Byte_Offset++)
                                {
                                    if (G_Buffer_Info_Block[G_Block_Byte_Offset] == 0x01) { G_Buffer_Info_Block[G_Block_Byte_Offset] = 0x00; }
                                }
                            }
                        }

                        int G_Block_Next_Index = 0;
                        for (int G_Block_Byte_Offset = 0; G_Block_Byte_Offset < G_Buffer_Info_Block.Length; G_Block_Byte_Offset++)
                        {
                            if (G_Buffer_Info_Block[G_Block_Byte_Offset] == 0xFF)
                            {
                                G_Block_Next_Index += 1;
                                G_File_Offset += G_Block_Size;
                            }
                            else { break; }
                        }
                        byte[] G_Block_Next = new byte[G_Block_Count];
                        Array.Copy(G_Buffer_Info_Block, G_Block_Next_Index, G_Block_Next, 0, G_Block_Next.Length - G_Block_Next_Index);
                        G_Buffer_Info_Block = G_Block_Next;
                        if (G_File_Offset >= G_File_Length)
                        {
                            if (File.Exists(G_Write_Binary) && !File.Exists(G_Absolute)) { File.Move(G_Write_Binary, G_Absolute); G_Write_Response = 201; }
                            else { SetResponse(400); return; }
                        }

                        long G_Block_Next_Start = -1;
                        long G_Block_Next_End = -1;
                        for (int G_Block_Byte_Offset = 0; G_Block_Byte_Offset < G_Buffer_Info_Block.Length; G_Block_Byte_Offset++)
                        {
                            if (G_Buffer_Info_Block[G_Block_Byte_Offset] == 0x00)
                            {
                                G_Buffer_Info_Block[G_Block_Byte_Offset] = 0x01;
                                G_Block_Next_Start = G_File_Offset + G_Block_Byte_Offset * G_Block_Size;
                                if (G_Block_Next_Start >= G_File_Length) { G_Block_Next_Start = -1; break; }
                                G_Block_Next_End = G_Block_Next_Start + G_Block_Size;
                                if (G_Block_Next_End >= G_File_Length) { G_Block_Next_End = G_File_Length - 1; }
                                else { G_Block_Next_End -= 1; }
                                break;
                            }
                        }
                        if (G_Block_Next_Start >= 0 || G_Block_Next_End >= 0) { SetRange(G_Block_Next_Start, G_Block_Next_End); }

                        G_Buffer_Info = new byte[S_Write_Info_Size];
                        Array.Copy(Encoding.UTF8.GetBytes(S_Write_Magic), 0, G_Buffer_Info, 0, 8);
                        Array.Copy(G_Buffer_Info_Header, 0, G_Buffer_Info, 8, G_Buffer_Info_Header.Length);
                        Array.Copy(G_Buffer_Info_Block, 0, G_Buffer_Info, G_Record_Offset, G_Buffer_Info_Block.Length);
                        Array.Copy(BitConverter.GetBytes(G_File_Offset), 0, G_Buffer_Info, 16, 8);
                        X_Stream_Info.Seek(0, SeekOrigin.Begin);
                        X_Stream_Info.Write(G_Buffer_Info, 0, G_Buffer_Info.Length);
                        CloseStream();
                        if (G_Write_Response == 201) { if (File.Exists(G_Write_Info)) { File.Delete(G_Write_Info); } }
                        if (G_Write_Response == 0) { SetResponse(204); return; }
                        SetResponse(G_Write_Response);
                    }
                    else
                    {
                        string P_HTML_Content = GetFile(GetParameter("Page-Write"));
                        if (string.IsNullOrEmpty(P_HTML_Content)) { SetResponse(403); return; }
                        else { Response.Write(P_HTML_Content); }
                    }
                }
                catch (Exception ex)
                {
                    if (I_Debug)
                    {
                        WriteLog(ex.ToString());
                    }
                    else
                    {
                        SetResponse(400);
                    }
                }
                return;
            }

            // File explore procedure
            if (X_Permission.Contains("r") || X_Permission.Contains("w"))
            {
                bool P_HTML = true;
                if (R_Action.ToLower().StartsWith("t")) { P_HTML = false; }
                string P_HTML_Content = "";
                string P_Text_Content = "";
                string P_Parameter_Directory = "";
                string P_Parameter_Create = "&r=" + S_Recursive_Write.ToString();

                int P_Recursive = VerifyRecursive();
                string P_Recursive_Value = "";
                if (!string.IsNullOrEmpty(U_Recursive) && (X_Permission.Contains("x") || string.IsNullOrEmpty(R_Recursive)))
                {
                    int U_Recursive_Integer = 0;
                    bool U_Recursive_IsInteger = int.TryParse(U_Recursive, out U_Recursive_Integer);
                    if (U_Recursive_IsInteger) { P_Recursive_Value = U_Recursive; }
                    else { P_Recursive_Value = (GetRecursive() + 1).ToString(); }
                }
                else if (!string.IsNullOrEmpty(R_Recursive)) { P_Recursive_Value = R_Recursive; }
                if (!string.IsNullOrEmpty(P_Recursive_Value)) { P_Parameter_Directory += "&r=" + P_Recursive_Value; P_Parameter_Create = "&r=" + (Convert.ToInt32(P_Recursive_Value) + S_Recursive_Write).ToString(); }
                string P_Recursive_Root = ""; if (!string.IsNullOrEmpty(R_Recursive)) { P_Recursive_Root = GetSignature("d=" + GetRecursiveRoot() + "&r=" + R_Recursive, GetParameter("Token-Request-Alias"), true); }

                if (P_HTML)
                {
                    // Home path
                    string P_Bucket_Home = GetSignature("", GetParameter("Token-Request-Alias"), true); if (!string.IsNullOrEmpty(P_Recursive_Root)) { P_Bucket_Home = P_Recursive_Root; }
                    P_HTML_Content += "<!DOCTYPE html><html><head><title>" + GetParameter("Main-Title") + "</title><style type=\"text/css\">body { position: relative; margin: 0 auto; padding: 30px; width: 800px; font-family: Microsoft YaHei; background: url(" + GetParameter("Background-Image") + ") no-repeat center center fixed; background-size: cover; } a { text-decoration: none; word-break: break-all; }</style></head><body>" + GetParameter("Custom-JavaScript") + "<br><div style=\"background: " + GetParameter("MainTitle-Background-Color") + "; text-align: center; word-break: break-all; margin: 10px; margin-left: 20%; margin-right: 20%; padding: 10px;\"><a style=\"color: " + GetParameter("MainTitle-Text-Color") + "; font-size: 24px; font-weight: bold;\" href=\"" + P_Bucket_Home + "\">" + GetParameter("Main-Title") + "</a></div>";
                    if (!string.IsNullOrEmpty(GetParameter("Sub-Title"))) { P_HTML_Content += "<div style=\"background: " + GetParameter("SubTitle-Background-Color") + "; text-align: center; word-break: break-all; margin-top: 0px; margin-left: 10%; margin-right: 10%;\"><p style=\"color: " + GetParameter("SubTitle-Text-Color") + "; font-size: 16px; font-weight: bold; padding: 10px;\">" + GetParameter("Sub-Title") + "</p></div>"; }
                    P_HTML_Content += "<br>";
                }

                foreach (string P_Bucket in S_Bucket)
                {
                    string P_Bucket_Name = P_Bucket.Split(' ')[0].Replace("<>", " ");
                    if (VerifyBucketAccess(P_Bucket_Name))
                    {
                        string P_Bucket_Directory = R_Directory; if (string.IsNullOrEmpty(P_Bucket_Directory)) { P_Bucket_Directory = P_Bucket_Name; }
                        string P_Bucket_Absolute = GetAbsolutePath(P_Bucket_Directory);

                        // Bucket path
                        string P_Bucket_Root = GetSignature("d=" + PathEncode(P_Bucket_Name), GetParameter("Token-Request-Alias"), true); if (!string.IsNullOrEmpty(P_Recursive_Root)) { P_Bucket_Root = P_Recursive_Root; }
                        P_HTML_Content += "<div style=\"background: " + GetParameter("Bucket-Background-Color") + "; text-align: center; word-break: break-all; border-radius: 20px; padding: 5px; margin: 10px; font-size: 18px;\"><a style=\"color: " + GetParameter("Bucket-Text-Color") + ";\" href=\"" + P_Bucket_Root + "\">" + P_Bucket_Directory + "</a></div>";

                        if (!(string.IsNullOrEmpty(R_Directory) && !GetBoolean(GetParameter("Show-Files"))))
                        {
                            bool P_Color_Even = false;

                            P_HTML_Content += "<table style=\"width: 100%; font-size: 16px;\"><tbody>";
                            if (P_Recursive > 0 && !string.IsNullOrEmpty(R_Path))
                            {
                                // Parent path
                                P_Color_Even = !P_Color_Even;
                                P_HTML_Content += ("<tr><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(P_Color_Even) + ";\" href=\"" + GetSignature("d=" + GetParent(P_Bucket_Directory) + P_Parameter_Directory, GetParameter("Token-Request-Alias"), true) + "\">/..</a></td><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; text-align: center; width: 15%;\"></td></tr>");
                            }

                            // List all files
                            DirectoryInfo P_Absolute = new DirectoryInfo(P_Bucket_Absolute);
                            if (X_Permission.Contains("r")) {
                                foreach (FileInfo P_File in P_Absolute.GetFiles("*.*", SearchOption.TopDirectoryOnly))
                                {
                                    if (!IsExclude(P_File.Name))
                                    {
                                        // Download link
                                        P_Color_Even = !P_Color_Even;
                                        string P_FileHref = GetSignature("d=" + PathEncode(P_Bucket_Directory) + "&f=" + PathEncode(P_File.Name), GetParameter("Token-Data-Alias"), false);
                                        if (P_HTML)
                                        {
                                            P_HTML_Content += ("<tr><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(P_Color_Even) + ";\" href=\"" + P_FileHref + "\" target=\"_blank\">" + P_File.Name + "</a></td><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; color: " + GetItemTextColor(P_Color_Even) + "; text-align: center; width: 15%;\">" + FileSizeToString(P_File.Length) + "</td>");
                                        }
                                        else
                                        {
                                            P_Text_Content += Request.Url.AbsoluteUri.Split('?')[0] + P_FileHref + Environment.NewLine;
                                        }
                                        if (X_Permission.Contains("x"))
                                        {
                                            P_HTML_Content += ("<td style=\"background: " + GetParameter("Delete-Background-Color") + "; text-align: center; width: 10%;\"><a style=\"color: " + GetParameter("Delete-Text-Color") + "; cursor: pointer;\" onclick=\"deleteData('" + L_Delete_File + "\\r\\n\\r\\n" + P_File.Name + "','" + GetSignature("d=" + PathEncode(P_Bucket_Directory) + "&y=" + PathEncode(P_File.Name), GetParameter("Token-General-Alias"), true) + "')\">" + L_Delete + "</a></td>");
                                        }
                                        P_HTML_Content += ("</tr>");
                                    }
                                }
                            }

                            // List all directories
                            foreach (DirectoryInfo P_Directory in P_Absolute.GetDirectories())
                            {
                                if (!IsExclude(P_Directory.Name))
                                {
                                    // Directory link
                                    P_Color_Even = !P_Color_Even;
                                    P_HTML_Content += ("<tr><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(P_Color_Even) + ";\" href=\"" + GetSignature("d=" + PathEncode(P_Bucket_Directory) + "\\" + PathEncode(P_Directory.Name) + P_Parameter_Directory, GetParameter("Token-Request-Alias"), true) + "\">/" + P_Directory.Name + "</a></td><td style=\"background: " + GetItemBackgroundColor(P_Color_Even) + "; text-align: center; width: 15%;\"></td>");
                                    if (X_Permission.Contains("x"))
                                    {
                                        P_HTML_Content += ("<td style=\"background: " + GetParameter("Delete-Background-Color") + "; text-align: center; width: 10%;\"><a style=\"color: " + GetParameter("Delete-Text-Color") + "; cursor: pointer;\" onclick=\"deleteData('" + L_Delete_Directory + "\\r\\n\\r\\n" + P_Directory.Name + "','" + GetSignature("d=" + PathEncode(P_Bucket_Directory) + "&y=" + PathEncode("/" + P_Directory.Name), GetParameter("Token-General-Alias"), true) + "')\">" + L_Delete + "</a></td>");
                                    }
                                    P_HTML_Content += ("</tr>");
                                }
                            }

                            string P_Create = "onclick=\"create()\"";
                            if (X_Permission.Contains("w")) { P_Create = "href=\"" + GetSignature("d=" + PathEncode(P_Bucket_Directory) + P_Parameter_Create, GetParameter("Token-Request-Alias"), true) + "\" target=\"_blank\""; }
                            P_HTML_Content += "</tbody></table><br><table style=\"width: 50%; margin: auto; table-layout: fixed; text-align: center; font-size: 14px; font-weight: bold;\"><tbody><tr><td style=\"background: " + GetItemBackgroundColor(false) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(false) + "; cursor: pointer;\" " + P_Create + ">" + L_Create + "</a></td><td style=\"background: " + GetItemBackgroundColor(false) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(false) + "; cursor: pointer;\" onclick=\"refresh()\">" + L_Refresh + "</a></td><td style=\"background: " + GetItemBackgroundColor(false) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(false) + "; cursor: pointer;\" onclick=\"showOptions()\">" + L_Options + "</a></td><td style=\"background: " + GetItemBackgroundColor(false) + "; padding: 5px;\"><a style=\"color: " + GetItemTextColor(false) + "; cursor: pointer;\" onclick=\"logout()\">" + L_Logout + "</a></td></tr></tbody></table><br>";
                        }
                    }
                }
                if (!string.IsNullOrEmpty(GetParameter("Copyright-Information"))) { P_HTML_Content += "<br><div style=\"background: " + GetParameter("Copyright-Background-Color") + "; text-align: center; word-break: break-all; border-radius: 20px; margin: 10px; margin-left: 20%; margin-right: 20%;\"><p style=\"color: " + GetParameter("Copyright-Text-Color") + "; font-size: 14px; font-weight: bold; padding: 5px;\">" + GetParameter("Copyright-Information") + "</p></div>"; }
                P_HTML_Content += "<div id=\"mask\" style=\"display: none; position: fixed; top: 0%; left: 0%; width: 100%; height: 100%; background-color: black; opacity: 0.5; z-index: 1000;\"></div><div id=\"options\" style=\"display: none; position: fixed; width: 400px; height: 320px; left: 50%; top: 50%; margin-left: -200px; margin-top: -160px; z-index: 1001; overflow: auto;\"><table style=\"width: 100%; text-align: center; font-size: 16px; background: rgba(80, 80, 80, 1); border: 2px solid #202326;\"><tbody><tr><td style=\"background: rgba(38, 50, 56, 1);\" colspan=\"2\"><p style=\"text-align: center; font-size: 18px; color: white; margin: 10px;\">" + L_Options + "</p></td></tr><tr style=\"height: 5px;\"></tr><tr><td style=\"background: rgba(150, 162, 169, 1); padding: 5px; width: 25%;\"><p style=\"color: white; margin: 0px;\">" + L_Action + "</p></td><td style=\"background: rgba(220, 220, 220, 1); padding: 5px;\"><input id=\"action\" type=\"text\" style=\"font-size: 18px; width: 95%;\" value=\"\"></td></tr><tr><td style=\"background: rgba(150, 162, 169, 1); padding: 5px; width: 25%;\"><p style=\"color: white; margin: 0px;\">" + L_Expire + "</p></td><td style=\"background: rgba(220, 220, 220, 1); padding: 5px;\"><input id=\"expire\" type=\"text\" style=\"font-size: 18px; width: 95%;\" value=\"\"></td></tr><tr><td style=\"background: rgba(150, 162, 169, 1); padding: 5px; width: 25%;\"><p style=\"color: white; margin: 0px;\">" + L_Host + "</p></td><td style=\"background: rgba(220, 220, 220, 1); padding: 5px;\"><input id=\"host\" type=\"text\" style=\"font-size: 18px; width: 95%;\" value=\"\"></td></tr><tr><td style=\"background: rgba(150, 162, 169, 1); padding: 5px; width: 25%;\"><p style=\"color: white; margin: 0px;\">" + L_Recursive + "</p></td><td style=\"background: rgba(220, 220, 220, 1); padding: 5px;\"><input id=\"recursive\" type=\"text\" style=\"font-size: 18px; width: 95%;\" value=\"\"></td></tr><tr><td style=\"background: rgba(150, 162, 169, 1); padding: 5px; width: 25%;\"><p style=\"color: white; margin: 0px;\">" + L_Token + "</p></td><td style=\"background: rgba(220, 220, 220, 1); padding: 5px;\"><input id=\"token\" type=\"text\" style=\"font-size: 18px; width: 95%;\" value=\"\"></td></tr></tbody></table><table style=\"width: 100%; text-align: center; font-size: 18px; font-weight: bold; background: rgba(88, 88, 88, 1); color: white;\" cellspacing=\"10\"><tbody><tr><td style=\"background: rgba(66, 66, 66, 1); padding: 5px; width: 50%; height: 25px; \"><a style=\"cursor: pointer;\" onclick=\"setOptions()\">" + L_OK + "</a></td><td style=\"background: rgba(66, 66, 66, 1); padding: 5px; width: 50%; height: 25px;\"><a style=\"cursor: pointer;\" onclick=\"hideOptions()\">" + L_Cancel + "</a></td></tr></tbody></table></div>";
                P_HTML_Content += "<br><br><scr" + "ipt type=\"text/javascript\">var handlingFlag=false;function deleteData(confirmMessage,requestLink){if(handlingFlag==false){if(confirm(confirmMessage)){handlingFlag=true;var xmlhttp;xmlhttp=new XMLHttpRequest();xmlhttp.onreadystatechange=function(){if(xmlhttp.readyState==4){if(xmlhttp.status==204){window.location.reload();}else{handlingFlag=false;}}};xmlhttp.open(\"GET\",requestLink,true);xmlhttp.send()}}};function create(){alert('" + L_Create_Forbidden + "');};function logout(){handlingFlag=true;var url=window.location.href.split(/[?#]/)[0];document.execCommand(\"ClearAuthenticationCache\");var xmlhttp;xmlhttp=new XMLHttpRequest();xmlhttp.onreadystatechange=function(){if(xmlhttp.readyState==4){window.location.href=url;}};if(navigator.userAgent.indexOf(\"Firefox\")>-1){xmlhttp.open(\"GET\",url+\"?x=quit\",true,\"anonymous\",\"\");}else{xmlhttp.open(\"GET\",url+\"?x=quit\",true);xmlhttp.setRequestHeader(\"Authorization\",\"Basic Og==\");}xmlhttp.send();};function showOptions(){document.getElementById('mask').style.display='block';document.getElementById('options').style.display='block';};function hideOptions(){document.getElementById('options').style.display='none';document.getElementById('mask').style.display='none';};function setOptions(){var options='';var value=document.getElementById('action').value;if(value.length>0){options+='&x='+value;}value=document.getElementById('expire').value;var expire=parseFloat(value);if(expire!='NaN'){if(expire>0&&expire<1000000){value=Math.ceil(new Date().getTime()/1000+expire*60).toString();}}if(value.length>0){options+='&xe='+value;}value=document.getElementById('host').value;if(value.length>0){options+='&xh='+value;}value=document.getElementById('recursive').value;if(value.length>0){options+='&xr='+value;}value=document.getElementById('token').value;if(value.length>0){options+='&xt='+value;}if(options.length>0){if(window.location.href.indexOf('?')>-1){options=window.location.href+options;}else{options=window.location.href+'?'+options.substring(1);}window.location.href=options;}else{hideOptions();}};function refresh(){location.reload();};</scr" + "ipt>";
                P_HTML_Content += "</body></html>";
                if (P_HTML) { Response.Write(P_HTML_Content); }
                else { Response.Write(P_Text_Content); }
                WriteLog("(" + X_Group + ") " + R_Directory);
                return;
            }

            SetResponse(403);
        }
        catch (Exception ex)
        {
            if (I_Debug)
            {
                WriteLog(ex.ToString());
                throw;
            }
            else
            {
                SetResponse(403);
            }
        }
        finally
        {
            CloseStream();
            Response.End();
            Response.Close();
        }
    }

    // Global variables
    string R_Action = "";
    string R_APIKey = "";
    bool R_Authorized = false;
    string R_Absolute = "";
    string R_Block = "";
    string R_Bucket = "";
    string R_Directory = "";
    string R_Expire = "";
    string R_File = "";
    string R_Group = "";
    string R_Host = "";
    string R_Path = "";
    string R_Recursive = "";
    string R_Remove = "";
    string R_Signature = "";
    string R_Token = "";
    string R_Write = "";
    List<string> S_Bucket = new List<string>();
    List<string> S_Exclude = new List<string>();
    List<string> S_Group = new List<string>();
    NameValueCollection S_Parameter = new NameValueCollection();
    int S_Recursive_Write = 1000;
    string U_Expire = "";
    string U_Host = "";
    string U_Language = "en";
    string U_Recursive = "";
    string U_Token = "";
    bool X_BindIP = false;
    string X_Bucket = "";
    double X_Expire = 0;
    string X_Group = "";
    string X_Permission = "";
    string X_Private = "";
    string X_Signature = "";
    FileStream X_Stream_Info = null;
    FileStream X_Stream_Binary = null;
    bool X_Write = false;
    bool X_Write_Cancel = false;

    // Runtime functions
    #region General

    public void CloseStream()
    {
        if (X_Stream_Info != null) { X_Stream_Info.Close(); X_Stream_Info.Dispose(); X_Stream_Info = null; }
        if (X_Stream_Binary != null) { X_Stream_Binary.Close(); X_Stream_Binary.Dispose(); X_Stream_Binary = null; }
    }

    public string DecryptToken(string param1) {
        try
        {
            if (param1.Contains("-")) { param1 = param1.Split('-')[1]; }
            if (param1.Contains("_")) { param1 = param1.Split('_')[1]; }
            string _loc_1 = AES_Decrypt(param1.Substring(8, param1.Length - 8), HexToBytes(SHA1(param1.Substring(0, 8).ToUpper() + ":" + X_Private).Substring(0, 32)), new byte[16]);
            string _loc_2 = BytesToHex(Base32Decode(param1.Substring(0, 8))).Substring(0, 8);
            if (_loc_2 == CRC32(_loc_1 + ":" + X_Private))
            {
                return _loc_1.Substring(5);
            }
            foreach (string _loc_3 in S_Group)
            {
                if (_loc_2 == CRC32(_loc_1 + ":" + _loc_3.Split(' ')[0] + ":" + _loc_3.Split(' ')[1] + ":" + X_Private))
                {
                    SetGroup(_loc_3.Split(' ')[0]);
                    return _loc_1.Substring(5);
                }
            }
            return "";
        }
        catch
        {
            return "";
        }
    }

    public string EncryptToken(string param1, string param2, bool param3)
    {
        try
        {
            param1 = GetRandomBase32String(5) + param1;
            byte[] _loc_1 = new byte[4];
            if (param3)
            {
                _loc_1 = CRC32_Bytes(Encoding.UTF8.GetBytes(param1 + ":" + X_Group + ":" + GetGroupSecret(X_Group) + ":" + X_Private));
            }
            else
            {
                _loc_1 = CRC32_Bytes(Encoding.UTF8.GetBytes(param1 + ":" + X_Private));
            }
            byte[] _loc_2 = new byte[5];
            Array.Copy(_loc_1, _loc_2, _loc_1.Length);
            _loc_2[4] = (byte)new Random(GetSeed()).Next(256);
            string _loc_3 = Base32Encode(_loc_2).Substring(0, 8);
            string _loc_4 = "";
            if (param2.Length > 0)
            {
                if (param2.EndsWith("-") || param2.EndsWith("_")) { _loc_4 = param2; }
                else { _loc_4 = param2 + "-"; }
            }
            return _loc_4 + _loc_3 + AES_Encrypt(param1, HexToBytes(SHA1(_loc_3 + ":" + X_Private).Substring(0, 32)), new byte[16]);
        }
        catch
        {
            return "";
        }
    }

    public bool GetBoolean(string param1)
    {
        int _loc_1 = 0;
        bool _loc_2 = int.TryParse(param1, out _loc_1);
        if (string.IsNullOrEmpty(param1) || (_loc_1 == 0 && _loc_2) || param1 == "-" || param1.ToLower().StartsWith("f") || param1.ToLower().StartsWith("n")) { return false; }
        return true;
    }

    public string GetCollectionValue(NameValueCollection param1, string param2)
    {
        if (!string.IsNullOrEmpty(param1[param2])) { return param1[param2]; }
        return "";
    }

    public string GetFile(string param1)
    {
        try
        {
            if (!File.Exists(param1)) { return ""; }
            return File.ReadAllText(param1, Encoding.UTF8);
        }
        catch
        {
            return "";
        }
    }

    public string GetGroupSecret(string GroupName)
    {
        if (string.IsNullOrEmpty(GroupName)) { return ""; }
        foreach (string _loc_1 in S_Group)
        {
            if (_loc_1.Split(' ')[0] == GroupName) { return _loc_1.Split(' ')[1]; }
        }
        return "";
    }

    public string GetItemBackgroundColor(bool param1)
    {
        if (param1) { return GetParameter("Item-Background-Color-Odd"); }
        else { return GetParameter("Item-Background-Color-Even"); }
    }

    public string GetItemTextColor(bool param1)
    {
        if (param1) { return GetParameter("Item-Text-Color-Odd"); }
        else { return GetParameter("Item-Text-Color-Even"); }
    }

    public long GetLong(string param1)
    {
        long _loc_1 = 0;
        long.TryParse(param1, out _loc_1);
        return _loc_1;
    }

    public string GetParameter(string param1)
    {
        try
        {
            string _loc_1 = param1.Replace("-", "").Replace("_", "").ToUpper();
            if (string.IsNullOrEmpty(S_Parameter[_loc_1])) { return ""; }
            else { return S_Parameter[_loc_1]; }
        }
        catch
        {
            return "";
        }
    }

    public string GetParent(string param1)
    {
        string[] _loc_1 = param1.Split('\\');
        string _loc_2 = "";
        for (int _loc_3 = 0; _loc_3 < _loc_1.Length - 1; _loc_3++)
        {
            _loc_2 += _loc_1[_loc_3] + "\\";
        }
        return _loc_2.Substring(0, _loc_2.Length - 1);
    }

    public string GetQueryString(NameValueCollection param1)
    {
        string[] _loc_1 = (from _loc_2 in param1.AllKeys
                           from _loc_3 in param1.GetValues(_loc_2)
                           select string.Format("{0}={1}", HttpUtility.UrlEncode(_loc_2), HttpUtility.UrlEncode(_loc_3))).ToArray();
        return string.Join("&", _loc_1);
    }

    public int GetRecursive()
    {
        int _loc_1 = 0;
        foreach (char _loc_2 in R_Directory)
            if (_loc_2 == '\\') _loc_1++;
        return _loc_1;
    }

    public string GetRecursiveRoot()
    {
        int _loc_1 = Convert.ToInt32(R_Recursive);
        int _loc_2 = -1;
        int _loc_3 = -1;
        while (_loc_3 < _loc_1)
        {
            _loc_2 += 1;
            int _loc_4 = R_Directory.IndexOf('\\', _loc_2);
            if (_loc_4 < 0) { return R_Directory; }
            _loc_2 = _loc_4;
            _loc_3 += 1;
        }
        if (_loc_2 < 1) { return ""; }
        return R_Directory.Substring(0, _loc_2);
    }

    public string GetRequestHeader(string param1)
    {
        if (!string.IsNullOrEmpty(Request.Headers[param1])) { return Request.Headers[param1]; }
        return "";
    }

    public string GetSignature(string param1, string param2, bool param3)
    {
        string _loc_11 = "";
        if (X_Signature.Length == 0)
        {
            if (!string.IsNullOrEmpty(U_Expire) && X_Permission.Contains("x")) { _loc_11 = SetParameter(_loc_11, "e", U_Expire); }
            else if (!string.IsNullOrEmpty(R_Expire)) { _loc_11 = SetParameter(_loc_11, "e", R_Expire); }
            else if (X_Expire > 0) { _loc_11 = SetParameter(_loc_11, "e", Convert.ToInt64(X_Expire * 3600 + Time()).ToString()); }
            else if (!string.IsNullOrEmpty(U_Expire)) { _loc_11 = SetParameter(_loc_11, "e", U_Expire); }
            if (!string.IsNullOrEmpty(U_Host) && X_Permission.Contains("x")) { _loc_11 = SetParameter(_loc_11, "h", U_Host); }
            else if (!string.IsNullOrEmpty(R_Host)) { _loc_11 = SetParameter(_loc_11, "h", R_Host); }
            else if (X_BindIP) { _loc_11 = SetParameter(_loc_11, "h", GetUserIP()); }
            else if (!string.IsNullOrEmpty(U_Host)) { _loc_11 = SetParameter(_loc_11, "h", U_Host); }
            if (_loc_11.Length == 0) { X_Signature = "-"; }
            else { X_Signature = _loc_11; }
        }
        else if (X_Signature.Length > 1) { _loc_11 = X_Signature; }
        if (param3 && !string.IsNullOrEmpty(X_Group)) { _loc_11 = SetParameter(_loc_11, "g", X_Group); }
        if (param1.Length == 0) { param1 = _loc_11; }
        else if (param1.Length > 0 && _loc_11.Length > 0) { param1 = _loc_11 + "&" + param1; }
        if (string.IsNullOrEmpty(param2)) { param2 = "t"; }
        bool _loc_1 = GetBoolean(GetParameter("Token-Enable"));
        string _loc_4 = U_Token; if (!string.IsNullOrEmpty(U_Token)) { _loc_1 = true; if (U_Token.Length == 1 && char.IsPunctuation(U_Token.ToCharArray()[0])) { _loc_4 = ""; } }
        if (_loc_1)
        {
            return "?" + param2 + "=" + EncryptToken(param1, _loc_4, param3);
        }
        else
        {
            NameValueCollection _loc_2 = ParseQueryString(param1);
            string _loc_3 = ":";
            if (param3) { _loc_3 = GetCollectionValue(_loc_2, "g") + ":" + GetGroupSecret(GetCollectionValue(_loc_2, "g")); }
            _loc_3 += ":" + GetCollectionValue(_loc_2, "d") + ":" + GetCollectionValue(_loc_2, "r") + ":" + GetCollectionValue(_loc_2, "f") + ":" + GetCollectionValue(_loc_2, "e") + ":" + GetCollectionValue(_loc_2, "h") + ":" + X_Private;
            return "?k=" + SHA1(_loc_3) + "&" + GetQueryString(_loc_2);
        }
    }

    public string GetUserIP()
    {
        return HttpContext.Current.Request.UserHostAddress;
    }

    public bool IsExclude(string param1)
    {
        foreach (string _loc_1 in S_Exclude)
        {
            if (_loc_1.ToLower() == param1.ToLower() && (_loc_1.Length >= 1))
            {
                return true;
            }
            if (_loc_1.ToLower().ToLower().StartsWith("*") && param1.ToLower().EndsWith(_loc_1.ToLower().Substring(1, _loc_1.Length - 1)) && (_loc_1.Length >= 2))
            {
                return true;
            }
            if (_loc_1.ToLower().ToLower().EndsWith("*") && param1.ToLower().StartsWith(_loc_1.ToLower().Substring(0, _loc_1.Length - 1)) && (_loc_1.Length >= 2))
            {
                return true;
            }
            if (_loc_1.ToLower().ToLower().StartsWith("*") && _loc_1.ToLower().EndsWith("*") && param1.ToLower().Contains(_loc_1.ToLower().Substring(1, _loc_1.Length - 2)) && (_loc_1.Length >= 3))
            {
                return true;
            }
        }
        return false;
    }

    public void LoadConfig()
    {
        FileStream _loc_1 = new FileStream(I_Config, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite);
        StreamReader _loc_2 = new StreamReader(_loc_1);
        List<string> _loc_3 = new List<string>();
        string _loc_4;
        while ((_loc_4 = _loc_2.ReadLine()) != null) { _loc_3.Add(_loc_4.Trim()); }
        _loc_2.Close();
        _loc_1.Close();
        Regex _loc_5 = new Regex("[ ]{2,}", RegexOptions.None);
        foreach (string _loc_6 in _loc_3)
        {
            if (!string.IsNullOrEmpty(_loc_6) && !_loc_6.StartsWith("#") && _loc_6.Contains("="))
            {
                string _loc_7 = _loc_5.Replace(_loc_6, " ");
                string _loc_8 = _loc_7.Substring(0, _loc_7.IndexOf('='));
                string _loc_9 = _loc_7.Substring(_loc_8.Length + 1).Trim();
                _loc_8 = _loc_8.Trim().Replace("-", "").Replace("_", "").ToUpper();
                switch (_loc_8)
                {
                    case "BUCKET":
                        S_Bucket.Add(_loc_9);
                        break;
                    case "EXCLUDE":
                        S_Exclude.Add(_loc_9);
                        break;
                    case "GROUP":
                        S_Group.Add(_loc_9);
                        break;
                    default:
                        S_Parameter.Add(_loc_8, _loc_9);
                        break;
                }
            }
        }
    }

    public void LoadParameter(NameValueCollection param1)
    {
        R_Directory = "";
        R_Expire = "";
        R_File = "";
        R_Group = "";
        R_Host = "";
        R_Recursive = "";
        if (!string.IsNullOrEmpty(GetParameter("Private-Key"))) { X_Private = GetParameter("Private-Key"); }
        if (!string.IsNullOrEmpty(param1["akey"])) { param1 = ReplaceParameter(param1, "akey", "a"); }
        if (!string.IsNullOrEmpty(param1["api"])) { param1 = ReplaceParameter(param1, "api", "a"); }
        if (!string.IsNullOrEmpty(param1["block"])) { param1 = ReplaceParameter(param1, "block", "b"); }
        if (!string.IsNullOrEmpty(param1["directory"])) { param1 = ReplaceParameter(param1, "directory", "d"); }
        if (!string.IsNullOrEmpty(param1["exp"])) { param1 = ReplaceParameter(param1, "exp", "e"); }
        if (!string.IsNullOrEmpty(param1["expire"])) { param1 = ReplaceParameter(param1, "expire", "e"); }
        if (!string.IsNullOrEmpty(param1["file"])) { param1 = ReplaceParameter(param1, "file", "f"); }
        if (!string.IsNullOrEmpty(param1["group"])) { param1 = ReplaceParameter(param1, "group", "g"); }
        if (!string.IsNullOrEmpty(param1["host"])) { param1 = ReplaceParameter(param1, "host", "h"); }
        if (!string.IsNullOrEmpty(param1["key"])) { param1 = ReplaceParameter(param1, "key", "k"); }
        if (!string.IsNullOrEmpty(param1["sign"])) { param1 = ReplaceParameter(param1, "sign", "k"); }
        if (!string.IsNullOrEmpty(param1["signature"])) { param1 = ReplaceParameter(param1,"signature", "k"); }
        if (!string.IsNullOrEmpty(param1["recursive"])) { param1 = ReplaceParameter(param1, "recursive", "r"); }
        if (!string.IsNullOrEmpty(param1["bizid"])) { param1 = ReplaceParameter(param1, "bizid", "r"); }
        if (!string.IsNullOrEmpty(param1["write"])) { param1 = ReplaceParameter(param1, "write", "w"); }
        if (!string.IsNullOrEmpty(param1["action"])) { param1 = ReplaceParameter(param1, "action", "x"); }
        if (!string.IsNullOrEmpty(param1["remove"])) { param1 = ReplaceParameter(param1, "remove", "y"); }
        if (!string.IsNullOrEmpty(param1["xexpire"])) { param1 = ReplaceParameter(param1, "xexpire", "xe"); }
        if (!string.IsNullOrEmpty(param1["xhost"])) { param1 = ReplaceParameter(param1, "xhost", "xh"); }
        if (!string.IsNullOrEmpty(param1["xrecursive"])) { param1 = ReplaceParameter(param1, "xrecursive", "xr"); }
        if (!string.IsNullOrEmpty(param1["xtoken"])) { param1 = ReplaceParameter(param1, "xtoken", "xt"); }
        if (!string.IsNullOrEmpty(GetParameter("Token-Data-Alias"))) { param1 = ReplaceParameter(param1, GetParameter("Token-Data-Alias"), "t"); }
        if (!string.IsNullOrEmpty(GetParameter("Token-Request-Alias"))) { param1 = ReplaceParameter(param1, GetParameter("Token-Request-Alias"), "t"); }
        if (!string.IsNullOrEmpty(GetParameter("Token-General-Alias"))) { param1 = ReplaceParameter(param1, GetParameter("Token-General-Alias"), "t"); }
        if (!string.IsNullOrEmpty(param1["a"])) { R_APIKey = param1["a"]; }
        if (!string.IsNullOrEmpty(param1["b"])) { R_Block = param1["b"]; }
        if (!string.IsNullOrEmpty(param1["d"])) { R_Directory = param1["d"]; }
        if (!string.IsNullOrEmpty(param1["e"])) { R_Expire = param1["e"]; }
        if (!string.IsNullOrEmpty(param1["f"])) { R_File = param1["f"]; }
        if (!string.IsNullOrEmpty(param1["g"])) { R_Group = param1["g"]; }
        if (!string.IsNullOrEmpty(param1["h"])) { R_Host = param1["h"]; }
        if (!string.IsNullOrEmpty(param1["k"])) { R_Signature = param1["k"]; }
        if (!string.IsNullOrEmpty(param1["r"])) { R_Recursive = param1["r"]; }
        if (!string.IsNullOrEmpty(param1["t"])) { R_Token = param1["t"]; }
        if (!string.IsNullOrEmpty(param1["w"])) { R_Write = param1["w"]; }
        if (!string.IsNullOrEmpty(param1["x"])) { R_Action = param1["x"]; }
        if (!string.IsNullOrEmpty(param1["y"])) { R_Remove = param1["y"]; }
        if (!string.IsNullOrEmpty(param1["xe"])) { U_Expire = param1["xe"]; }
        if (!string.IsNullOrEmpty(param1["xh"])) { U_Host = param1["xh"]; }
        if (!string.IsNullOrEmpty(param1["xr"])) { U_Recursive = param1["xr"]; }
        if (!string.IsNullOrEmpty(param1["xt"])) { U_Token = param1["xt"]; }
    }

    public void LoadPath()
    {
        if (R_Directory.Length > 0)
        {
            int _loc_1 = R_Directory.IndexOf('\\');
            if (_loc_1 > 0)
            {
                R_Bucket = R_Directory.Substring(0, _loc_1).Trim();
                R_Path = R_Directory.Substring(_loc_1 + 1).Trim();
            }
            else
            {
                R_Bucket = R_Directory.Trim();
            }
            R_Absolute = GetAbsolutePath(R_Directory);
        }
    }

    public string GetAbsolutePath(string param1)
    {
        int _loc_1 = param1.IndexOf('\\');
        string _loc_2 = param1;
        string _loc_3 = "";
        if (_loc_1 > 0)
        {
            _loc_2 = param1.Substring(0, _loc_1).Trim();
            _loc_3 = param1.Substring(_loc_1).Trim();
        }
        foreach (string _loc_4 in S_Bucket)
        {
            if (_loc_4.Split(' ')[0].Replace("<>", " ") == _loc_2) { return PathRegulation(_loc_4.Split(' ')[1].Replace("<>", " ").Trim()) + _loc_3; }
        }
        return "";
    }

    public NameValueCollection ParseQueryString(string param1)
    {
        if (param1.StartsWith("?")) { param1 = param1.Substring(1); }
        NameValueCollection _loc_1 = new NameValueCollection();
        foreach (string _loc_2 in param1.Split('&'))
        {
            string _loc_3 = _loc_2.Trim();
            int _loc_4 = _loc_3.IndexOf("=");
            if (_loc_4 > 0) {
                string _loc_5 = HttpUtility.UrlDecode(_loc_3.Substring(0, _loc_4));
                if (!string.IsNullOrEmpty(_loc_1[_loc_5])) { _loc_1.Remove(_loc_5); }
                _loc_1.Add(_loc_5, HttpUtility.UrlDecode(_loc_3.Substring(_loc_4 + 1)));
            }
        }
        return _loc_1;
    }

    public string PathEncode(string param1)
    {
        return param1.Replace("%", "%25").Replace("&", "%26").Replace("+", "%2b").Replace("=", "%3d");
    }

    public string PathRegulation(string param1)
    {
        param1 = param1.Trim().Replace("/", "\\").Replace("\\..", "").Replace("*", "");
        if (param1.StartsWith("\\") && !param1.StartsWith("\\\\")) { param1 = param1.Substring(1); }
        if (param1.EndsWith("\\")) { param1 = param1.Substring(0, param1.Length - 1); }
        return param1;
    }

    public NameValueCollection ReplaceParameter(NameValueCollection param1, string param2, string param3)
    {
        if (!string.IsNullOrEmpty(param1[param2]) && string.IsNullOrEmpty(param1[param3]) && !string.IsNullOrEmpty(param2) && !string.IsNullOrEmpty(param3) && param2 != param3)
        {
            param1.Add(param3, param1[param2]);
            param1.Remove(param2);
        }
        return param1;
    }

    public void SetAPIResponse()
    {
        NameValueCollection _loc_1 = ParseQueryString(Request.Url.Query);
        bool _loc_2 = false;
        if (!string.IsNullOrEmpty(R_Group)) { X_Group = R_Group; _loc_2 = true; }
        X_Permission = "rwx";
        if (!string.IsNullOrEmpty(_loc_1["a"])) { _loc_1.Remove("a"); }
        if (!string.IsNullOrEmpty(_loc_1["akey"])) { _loc_1.Remove("akey"); }
        if (!string.IsNullOrEmpty(_loc_1["api"])) { _loc_1.Remove("api"); }
        if (!string.IsNullOrEmpty(_loc_1["e"])) { _loc_1.Remove("e"); }
        if (!string.IsNullOrEmpty(_loc_1["exp"])) { _loc_1.Remove("exp"); }
        if (!string.IsNullOrEmpty(_loc_1["expire"])) { _loc_1.Remove("expire"); }
        if (!string.IsNullOrEmpty(_loc_1["g"])) { _loc_1.Remove("g"); }
        if (!string.IsNullOrEmpty(_loc_1["group"])) { _loc_1.Remove("group"); }
        if (!string.IsNullOrEmpty(_loc_1["h"])) { _loc_1.Remove("h"); }
        if (!string.IsNullOrEmpty(_loc_1["host"])) { _loc_1.Remove("host"); }
        if (!string.IsNullOrEmpty(_loc_1["xe"])) { _loc_1.Remove("xe"); }
        if (!string.IsNullOrEmpty(_loc_1["xexpire"])) { _loc_1.Remove("xexpire"); }
        if (!string.IsNullOrEmpty(_loc_1["xh"])) { _loc_1.Remove("xh"); }
        if (!string.IsNullOrEmpty(_loc_1["xhost"])) { _loc_1.Remove("xhost"); }
        if (!string.IsNullOrEmpty(_loc_1["xr"])) { _loc_1.Remove("xr"); }
        if (!string.IsNullOrEmpty(_loc_1["xrecursive"])) { _loc_1.Remove("xrecursive"); }
        if (!string.IsNullOrEmpty(_loc_1["xt"])) { _loc_1.Remove("xt"); }
        if (!string.IsNullOrEmpty(_loc_1["xtoken"])) { _loc_1.Remove("xtoken"); }
        string _loc_3 = GetSignature(GetQueryString(_loc_1), GetParameter("Token-General-Alias"), _loc_2);
        Response.Redirect(_loc_3, false);
    }

    public void SetGroup(string param1)
    {
        if (!string.IsNullOrEmpty(X_Group)) { return; }
        foreach (string _loc_1 in S_Group)
        {
            if (_loc_1.Split(' ')[0] == param1)
            {
                string[] _loc_2 = _loc_1.Split(' ');
                X_Group = _loc_2[0];
                if (_loc_2.Length >= 3) { X_Permission = _loc_2[2].ToLower(); }
                if (_loc_2.Length >= 4) { X_Bucket = _loc_2[3]; }
                if (_loc_2.Length >= 5) { double _loc_3 = 0; if (double.TryParse(_loc_2[4], out _loc_3)) { X_Expire = _loc_3; }}
                if (_loc_2.Length >= 6) { X_BindIP = GetBoolean(_loc_2[5]); }
            }
        }
    }

    string L_Action = "Action";
    string L_Cancel = "Cancel";
    string L_Create = "Create";
    string L_Create_Forbidden = "Sorry, you do not have permission to create resources.";
    string L_Delete = "Delete";
    string L_Delete_File = "Are you sure you want to permanently delete this file?";
    string L_Delete_Directory = "Are you sure you want to permanently delete this folder?";
    string L_Expire = "Expire";
    string L_Host = "Host";
    string L_Logout = "Logout";
    string L_OK = "OK";
    string L_Options = "Options";
    string L_Recursive = "Recursive";
    string L_Refresh = "Refresh";
    string L_Token = "Token";
    public void SetLanguage()
    {
        try
        {
            if (Request.UserLanguages != null) { U_Language = Request.UserLanguages[0].Split('-')[0].Trim(); }
            if (U_Language == "zh")
            {
                L_Action = "操作";
                L_Cancel = "取消";
                L_Create = "创建";
                L_Create_Forbidden = "抱歉，您没有创建资源项目的权限。";
                L_Delete = "删除";
                L_Delete_File = "确定要永久性地删除此文件吗?";
                L_Delete_Directory = "确定要永久性地删除此文件夹吗?";
                L_Expire = "有效时间";
                L_Host = "主机地址";
                L_Logout = "注销";
                L_OK = "确定";
                L_Options = "选项";
                L_Recursive = "递归级别";
                L_Refresh = "刷新";
                L_Token = "个性签名";
            }
        }
        catch
        {

        }
    }

    public string SetParameter(string param1, string param2, string param3)
    {
        if (param1.StartsWith("&")) { param1 = param1.Substring(1); }
        if (param1.EndsWith("&")) { param1 = param1.Substring(0, param1.Length - 1); }
        if (param1.Length == 0) { param1 = param2 + "=" + param3; }
        else { param1 = param1 + "&" + param2 + "=" + param3; }
        return param1;
    }

    public void SetRange(long param1, long param2)
    {
        Response.AddHeader("Range", "bytes=" + param1.ToString() + "-" + param2.ToString());
    }

    public void SetRecursive()
    {
        if (string.IsNullOrEmpty(R_Recursive)) { return; }
        int _loc_1 = 0;
        bool _loc_2 = int.TryParse(R_Recursive, out _loc_1);
        if (!_loc_2) { R_Recursive = GetRecursive().ToString(); return; }
        if (_loc_1 == S_Recursive_Write)
        {
            X_Write = true;
            R_Recursive = "";
        }
        else if (_loc_1 > S_Recursive_Write)
        {
            X_Write = true;
            R_Recursive = (_loc_1 - S_Recursive_Write).ToString();
        }
    }

    public void SetResponse(int param1)
    {
        if (param1 == 401)
        {
            string X_Page_Login = GetParameter("Page-Login");
            if (string.IsNullOrEmpty(X_Page_Login))
            {
                Response.StatusCode = 401;
                Response.AddHeader("WWW-Authenticate", "Basic realm=\"Authentication Required\"");
            }
            else
            {
                if (File.Exists(X_Page_Login)) { Response.StatusCode = 200; Response.Write(GetFile(X_Page_Login)); }
                else { Response.Redirect(X_Page_Login, false); }
            }
        }
        else { Response.StatusCode = param1; }
    }

    public byte[] StreamToBytes(Stream param1)
    {
        byte[] _loc_1 = new byte[1048576];
        using (MemoryStream _loc_2 = new MemoryStream())
        {
            int _loc_3;
            while ((_loc_3 = param1.Read(_loc_1, 0, _loc_1.Length)) > 0) { _loc_2.Write(_loc_1, 0, _loc_3); }
            return _loc_2.ToArray();
        }
    }

    public bool VerifyAPI()
    {
        foreach (string _loc_1 in GetParameter("API-Key").Split(' '))
        {
            if (_loc_1.Trim() == R_APIKey.Trim()) { return true; }
        }
        return false;
    }

    public bool VerifyBasicAuth()
    {
        string R_Username = Request.Form["Username"];
        string R_Password = Request.Form["Password"];
        string R_Authorization = HttpContext.Current.Request.Headers["Authorization"];
        if (!string.IsNullOrEmpty(R_Authorization) && R_Authorization.StartsWith("Basic"))
        {
            if (R_Authorization.Length <= 6) { return false; }
            string _loc_1 = Encoding.GetEncoding("iso-8859-1").GetString(Convert.FromBase64String(R_Authorization.Substring(6).Trim()));
            int _loc_2 = _loc_1.IndexOf(':');
            R_Username = _loc_1.Substring(0, _loc_2);
            R_Password = _loc_1.Substring(_loc_2 + 1);
        }
        if (string.IsNullOrEmpty(R_Username) || string.IsNullOrEmpty(R_Password)) { return false; }
        foreach (string _loc_3 in S_Group)
        {
            if (_loc_3.Split(' ')[0] == R_Username && _loc_3.Split(' ')[1] == R_Password)
            {
                SetGroup(R_Username);
                return true;
            }
        }
        WriteLog("(" + R_Username + ") Bad attempt.");
        return false;
    }

    public bool VerifyBucketAccess(string param1)
    {
        if (!string.IsNullOrEmpty(R_Bucket) && param1 != R_Bucket) { return false; }
        if (X_Bucket.Length <= 1) { return true; }
        foreach (string _loc_1 in X_Bucket.Split(';'))
        {
            if (_loc_1.Replace("<>", " ") == param1) { return true; }
        }
        return false;
    }

    public int VerifyRecursive()
    {
        if (string.IsNullOrEmpty(R_Recursive)) { return Int32.MaxValue; }
        return GetRecursive() - Convert.ToInt32(R_Recursive);
    }

    public bool VerifyRequest()
    {
        if (Request.Headers["Accept-Language"] == "zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4" || (!String.IsNullOrEmpty(Request.Headers["User-Agent"]) && Request.Headers["User-Agent"].Contains("Chrome/34.0.1847.131"))) { return false; }
        return true;
    }

    public bool VerifySignature()
    {
        if (R_Signature.ToUpper() == SHA1(R_Group + ":" + GetGroupSecret(R_Group) + ":" + R_Directory + ":" + R_Recursive + ":" + R_File + ":" + R_Expire + ":" + R_Host + ":" + X_Private)) { SetGroup(R_Group); return true; }
        return false;
    }

    public bool VerifyUserHost(string param1)
    {
        string UserHost = GetUserIP();
        string[] PermittedHosts = param1.Split('|');
        for (int _loc_1 = 0; _loc_1 < PermittedHosts.Length; _loc_1++)
        {
            if (PermittedHosts[_loc_1] == "*")
            {
                return true;
            }
            else if (PermittedHosts[_loc_1].StartsWith("*") && PermittedHosts[_loc_1].EndsWith("*") && UserHost.Contains(PermittedHosts[_loc_1].Substring(1, PermittedHosts[_loc_1].Length - 2)))
            {
                return true;
            }
            else if (PermittedHosts[_loc_1].StartsWith("*") && UserHost.EndsWith(PermittedHosts[_loc_1].Split('*')[1]))
            {
                return true;
            }
            else if (PermittedHosts[_loc_1].EndsWith("*") && UserHost.StartsWith(PermittedHosts[_loc_1].Split('*')[PermittedHosts[_loc_1].Split('*').Length - 2]))
            {
                return true;
            }
            else if (UserHost == PermittedHosts[_loc_1])
            {
                return true;
            }
        }
        return false;
    }

    #endregion

    #region AES

    public string AES_Encrypt(string param1, byte[] param2, byte[] param3)
    {
        byte[] _loc_1 = Encoding.UTF8.GetBytes(param1);
        RijndaelManaged _loc_2 = new RijndaelManaged();
        _loc_2.Key = param2;
        _loc_2.IV = param3;
        _loc_2.Mode = CipherMode.CBC;
        _loc_2.Padding = PaddingMode.PKCS7;
        return Base32Encode(_loc_2.CreateEncryptor().TransformFinalBlock(_loc_1, 0, _loc_1.Length));
    }

    public string AES_Decrypt(string param1, byte[] param2, byte[] param3)
    {
        byte[] _loc_1 = Base32Decode(param1);
        RijndaelManaged _loc_2 = new RijndaelManaged();
        _loc_2.Key = param2;
        _loc_2.IV = param3;
        _loc_2.Mode = CipherMode.CBC;
        _loc_2.Padding = PaddingMode.PKCS7;
        return Encoding.UTF8.GetString(_loc_2.CreateDecryptor().TransformFinalBlock(_loc_1, 0, _loc_1.Length));
    }

    #endregion

    #region Base32

    //Base32 constants
    const int Base32_InByteSize = 8;
    const int Base32_OutByteSize = 5;
    const string Base32_Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Base32Encode(byte[] param1)
    {
        if (param1 == null) { return null; }
        else if (param1.Length == 0) { return string.Empty; }
        StringBuilder builder = new StringBuilder(param1.Length * Base32_InByteSize / Base32_OutByteSize);
        int bytesPosition = 0;
        int bytesSubPosition = 0;
        byte outputBase32Byte = 0;
        int outputBase32BytePosition = 0;
        while (bytesPosition < param1.Length)
        {
            int bitsAvailableInByte = Math.Min(Base32_InByteSize - bytesSubPosition, Base32_OutByteSize - outputBase32BytePosition);
            outputBase32Byte <<= bitsAvailableInByte;
            outputBase32Byte |= (byte)(param1[bytesPosition] >> (Base32_InByteSize - (bytesSubPosition + bitsAvailableInByte)));
            bytesSubPosition += bitsAvailableInByte;
            if (bytesSubPosition >= Base32_InByteSize)
            {
                bytesPosition++;
                bytesSubPosition = 0;
            }
            outputBase32BytePosition += bitsAvailableInByte;
            if (outputBase32BytePosition >= Base32_OutByteSize)
            {
                outputBase32Byte &= 0x1F;
                builder.Append(Base32_Alphabet[outputBase32Byte]);
                outputBase32BytePosition = 0;
            }
        }
        if (outputBase32BytePosition > 0)
        {
            outputBase32Byte <<= (Base32_OutByteSize - outputBase32BytePosition);
            outputBase32Byte &= 0x1F;
            builder.Append(Base32_Alphabet[outputBase32Byte]);
        }
        return builder.ToString();
    }

    public static byte[] Base32Decode(string param1)
    {
        if (param1 == null) { return null; }
        else if (param1 == string.Empty) { return new byte[0]; }
        string base32StringUpperCase = param1.ToUpperInvariant();
        byte[] outputBytes = new byte[base32StringUpperCase.Length * Base32_OutByteSize / Base32_InByteSize];
        if (outputBytes.Length == 0) { return null; }
        int base32Position = 0;
        int base32SubPosition = 0;
        int outputBytePosition = 0;
        int outputByteSubPosition = 0;
        while (outputBytePosition < outputBytes.Length)
        {
            int currentBase32Byte = Base32_Alphabet.IndexOf(base32StringUpperCase[base32Position]);
            if (currentBase32Byte < 0) { return null; }
            int bitsAvailableInByte = Math.Min(Base32_OutByteSize - base32SubPosition, Base32_InByteSize - outputByteSubPosition);
            outputBytes[outputBytePosition] <<= bitsAvailableInByte;
            outputBytes[outputBytePosition] |= (byte)(currentBase32Byte >> (Base32_OutByteSize - (base32SubPosition + bitsAvailableInByte)));
            outputByteSubPosition += bitsAvailableInByte;
            if (outputByteSubPosition >= Base32_InByteSize)
            {
                outputBytePosition++;
                outputByteSubPosition = 0;
            }
            base32SubPosition += bitsAvailableInByte;
            if (base32SubPosition >= Base32_OutByteSize)
            {
                base32Position++;
                base32SubPosition = 0;
            }
        }
        return outputBytes;
    }

    #endregion

    #region CRC32

    bool CRC32_Initialized = false;
    uint[] CRC32_ChecksumTable = new uint[0x100];
    uint CRC32_Polynomial = 0xEDB88320;

    public string CRC32(string param1)
    {
        return BytesToHex(CRC32_Bytes(Encoding.UTF8.GetBytes(param1)));
    }

    public byte[] CRC32_Bytes(byte[] param1)
    {
        if (!CRC32_Initialized) { CRC32_Init(); }
        using (MemoryStream _loc_1 = new MemoryStream(param1))
            return CRC32_ComputeHash(_loc_1);
    }

    public void CRC32_Init()
    {
        for (uint _loc_1 = 0; _loc_1 < 0x100; ++_loc_1)
        {
            uint _loc_2 = _loc_1;
            for (int _loc_3 = 0; _loc_3 < 8; ++_loc_3)
                _loc_2 = ((_loc_2 & 1) != 0) ? (CRC32_Polynomial ^ (_loc_2 >> 1)) : (_loc_2 >> 1);
            CRC32_ChecksumTable[_loc_1] = _loc_2;
        }
    }

    public byte[] CRC32_ComputeHash(Stream param1)
    {
        uint _loc_1 = 0xFFFFFFFF;
        int _loc_2;
        while ((_loc_2 = param1.ReadByte()) != -1)
            _loc_1 = CRC32_ChecksumTable[(_loc_1 & 0xFF) ^ (byte)_loc_2] ^ (_loc_1 >> 8);
        byte[] _loc_3 = BitConverter.GetBytes(~_loc_1);
        Array.Reverse(_loc_3);
        return _loc_3;
    }

    #endregion

    #region File

    public string FileSizeToString(long param1)
    {
        string[] _loc_1 = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
        if (param1 == 0) { return "0 " + _loc_1[0]; }
        long _loc_2 = Math.Abs(param1);
        int _loc_3 = Convert.ToInt32(Math.Floor(Math.Log(_loc_2, 1024)));
        return (Math.Sign(param1) * Math.Round(_loc_2 / Math.Pow(1024, _loc_3), 2)).ToString() + " " + _loc_1[_loc_3];
    }

    public long GetFileSize(string param1)
    {
        if (File.Exists(param1))
        {
            FileInfo _loc_1 = new FileInfo(param1);
            return _loc_1.Length;
        }
        else
        {
            return 0;
        }
    }

    #endregion

    #region Hex

    public string BytesToHex(byte[] param1)
    {
        return BitConverter.ToString(param1).Replace("-", "").ToUpper();
    }

    public byte[] HexToBytes(string param1) {
        return Enumerable.Range(0, param1.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(param1.Substring(x, 2), 16)).ToArray();
    }

    #endregion

    #region Logging

    private static Dictionary<long, long> X_Log_Lock = new Dictionary<long, long>();
    public void WriteLog(string param1)
    {
        try
        {
            if (GetParameter("Log-File").Length > 3)
            {
                using (FileStream _loc_1 = new FileStream(GetParameter("Log-File"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite, 8, FileOptions.Asynchronous))
                {
                    Byte[] _loc_2 = Encoding.UTF8.GetBytes("[" + DateTime.Now.ToString() + "] [" + GetUserIP() + "] " + param1 + Environment.NewLine);
                    bool _loc_3 = true;
                    long _loc_4 = _loc_2.Length;
                    long _loc_5 = 0;
                    while (_loc_3)
                    {
                        try
                        {
                            if (_loc_5 >= _loc_1.Length)
                            {
                                _loc_1.Lock(_loc_5, _loc_4);
                                X_Log_Lock[_loc_5] = _loc_4;
                                _loc_3 = false;
                            }
                            else { _loc_5 = _loc_1.Length; }
                        }
                        catch
                        {
                            while (!X_Log_Lock.ContainsKey(_loc_5)) { _loc_5 += X_Log_Lock[_loc_5]; }
                        }
                    }
                    _loc_1.Seek(_loc_5, System.IO.SeekOrigin.Begin);
                    _loc_1.Write(_loc_2, 0, _loc_2.Length);
                    _loc_1.Close();
                }
            }
        }
        catch
        {

        }
    }

    #endregion

    #region MIME
    // External code reference from https://github.com/samuelneff/MimeTypeMap

    private static readonly Lazy<IDictionary<string, string>> _mappings = new Lazy<IDictionary<string, string>>(BuildMappings);

    private static IDictionary<string, string> BuildMappings()
    {
        var mappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {

                #region List of mime types
            
                // maps both ways,
                // extension -> mime type
                //   and
                // mime type -> extension
                //
                // any mime types on left side not pre-loaded on right side, are added automatically
                // some mime types can map to multiple extensions, so to get a deterministic mapping,
                // add those to the dictionary specifcially
                //
                // combination of values from Windows 7 Registry and 
                // from C:\Windows\System32\inetsrv\config\applicationHost.config
                // some added, including .7z and .dat
                //
                // Some added based on http://www.iana.org/assignments/media-types/media-types.xhtml
                // which lists mime types, but not extensions
                //
                {".323", "text/h323"},
                {".3g2", "video/3gpp2"},
                {".3gp", "video/3gpp"},
                {".3gp2", "video/3gpp2"},
                {".3gpp", "video/3gpp"},
                {".7z", "application/x-7z-compressed"},
                {".aa", "audio/audible"},
                {".AAC", "audio/aac"},
                {".aaf", "application/octet-stream"},
                {".aax", "audio/vnd.audible.aax"},
                {".ac3", "audio/ac3"},
                {".aca", "application/octet-stream"},
                {".accda", "application/msaccess.addin"},
                {".accdb", "application/msaccess"},
                {".accdc", "application/msaccess.cab"},
                {".accde", "application/msaccess"},
                {".accdr", "application/msaccess.runtime"},
                {".accdt", "application/msaccess"},
                {".accdw", "application/msaccess.webapplication"},
                {".accft", "application/msaccess.ftemplate"},
                {".acx", "application/internet-property-stream"},
                {".AddIn", "text/xml"},
                {".ade", "application/msaccess"},
                {".adobebridge", "application/x-bridge-url"},
                {".adp", "application/msaccess"},
                {".ADT", "audio/vnd.dlna.adts"},
                {".ADTS", "audio/aac"},
                {".afm", "application/octet-stream"},
                {".ai", "application/postscript"},
                {".aif", "audio/aiff"},
                {".aifc", "audio/aiff"},
                {".aiff", "audio/aiff"},
                {".air", "application/vnd.adobe.air-application-installer-package+zip"},
                {".amc", "application/mpeg"},
                {".anx", "application/annodex"},
                {".apk", "application/vnd.android.package-archive" },
                {".application", "application/x-ms-application"},
                {".art", "image/x-jg"},
                {".asa", "application/xml"},
                {".asax", "application/xml"},
                {".ascx", "application/xml"},
                {".asd", "application/octet-stream"},
                {".asf", "video/x-ms-asf"},
                {".ashx", "application/xml"},
                {".asi", "application/octet-stream"},
                {".asm", "text/plain"},
                {".asmx", "application/xml"},
                {".aspx", "application/xml"},
                {".asr", "video/x-ms-asf"},
                {".asx", "video/x-ms-asf"},
                {".atom", "application/atom+xml"},
                {".au", "audio/basic"},
                {".avi", "video/x-msvideo"},
                {".axa", "audio/annodex"},
                {".axs", "application/olescript"},
                {".axv", "video/annodex"},
                {".bas", "text/plain"},
                {".bcpio", "application/x-bcpio"},
                {".bin", "application/octet-stream"},
                {".bmp", "image/bmp"},
                {".c", "text/plain"},
                {".cab", "application/octet-stream"},
                {".caf", "audio/x-caf"},
                {".calx", "application/vnd.ms-office.calx"},
                {".cat", "application/vnd.ms-pki.seccat"},
                {".cc", "text/plain"},
                {".cd", "text/plain"},
                {".cdda", "audio/aiff"},
                {".cdf", "application/x-cdf"},
                {".cer", "application/x-x509-ca-cert"},
                {".cfg", "text/plain"},
                {".chm", "application/octet-stream"},
                {".class", "application/x-java-applet"},
                {".clp", "application/x-msclip"},
                {".cmd", "text/plain"},
                {".cmx", "image/x-cmx"},
                {".cnf", "text/plain"},
                {".cod", "image/cis-cod"},
                {".config", "application/xml"},
                {".contact", "text/x-ms-contact"},
                {".coverage", "application/xml"},
                {".cpio", "application/x-cpio"},
                {".cpp", "text/plain"},
                {".crd", "application/x-mscardfile"},
                {".crl", "application/pkix-crl"},
                {".crt", "application/x-x509-ca-cert"},
                {".cs", "text/plain"},
                {".csdproj", "text/plain"},
                {".csh", "application/x-csh"},
                {".csproj", "text/plain"},
                {".css", "text/css"},
                {".csv", "text/csv"},
                {".cur", "application/octet-stream"},
                {".cxx", "text/plain"},
                {".dat", "application/octet-stream"},
                {".datasource", "application/xml"},
                {".dbproj", "text/plain"},
                {".dcr", "application/x-director"},
                {".def", "text/plain"},
                {".deploy", "application/octet-stream"},
                {".der", "application/x-x509-ca-cert"},
                {".dgml", "application/xml"},
                {".dib", "image/bmp"},
                {".dif", "video/x-dv"},
                {".dir", "application/x-director"},
                {".disco", "text/xml"},
                {".divx", "video/divx"},
                {".dll", "application/x-msdownload"},
                {".dll.config", "text/xml"},
                {".dlm", "text/dlm"},
                {".doc", "application/msword"},
                {".docm", "application/vnd.ms-word.document.macroEnabled.12"},
                {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                {".dot", "application/msword"},
                {".dotm", "application/vnd.ms-word.template.macroEnabled.12"},
                {".dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
                {".dsp", "application/octet-stream"},
                {".dsw", "text/plain"},
                {".dtd", "text/xml"},
                {".dtsConfig", "text/xml"},
                {".dv", "video/x-dv"},
                {".dvi", "application/x-dvi"},
                {".dwf", "drawing/x-dwf"},
                {".dwg", "application/acad"},
                {".dwp", "application/octet-stream"},
                {".dxf", "application/x-dxf" },
                {".dxr", "application/x-director"},
                {".eml", "message/rfc822"},
                {".emf", "image/emf"},
                {".emz", "application/octet-stream"},
                {".eot", "application/vnd.ms-fontobject"},
                {".eps", "application/postscript"},
                {".es", "application/ecmascript"},
                {".etl", "application/etl"},
                {".etx", "text/x-setext"},
                {".evy", "application/envoy"},
                {".exe", "application/vnd.microsoft.portable-executable"},
                {".exe.config", "text/xml"},
                {".f4v", "video/mp4"},
                {".fdf", "application/vnd.fdf"},
                {".fif", "application/fractals"},
                {".filters", "application/xml"},
                {".fla", "application/octet-stream"},
                {".flac", "audio/flac"},
                {".flr", "x-world/x-vrml"},
                {".flv", "video/x-flv"},
                {".fsscript", "application/fsharp-script"},
                {".fsx", "application/fsharp-script"},
                {".generictest", "application/xml"},
                {".gif", "image/gif"},
                {".gpx", "application/gpx+xml"},
                {".group", "text/x-ms-group"},
                {".gsm", "audio/x-gsm"},
                {".gtar", "application/x-gtar"},
                {".gz", "application/x-gzip"},
                {".h", "text/plain"},
                {".hdf", "application/x-hdf"},
                {".hdml", "text/x-hdml"},
                {".hhc", "application/x-oleobject"},
                {".hhk", "application/octet-stream"},
                {".hhp", "application/octet-stream"},
                {".hlp", "application/winhlp"},
                {".hpp", "text/plain"},
                {".hqx", "application/mac-binhex40"},
                {".hta", "application/hta"},
                {".htc", "text/x-component"},
                {".htm", "text/html"},
                {".html", "text/html"},
                {".htt", "text/webviewhtml"},
                {".hxa", "application/xml"},
                {".hxc", "application/xml"},
                {".hxd", "application/octet-stream"},
                {".hxe", "application/xml"},
                {".hxf", "application/xml"},
                {".hxh", "application/octet-stream"},
                {".hxi", "application/octet-stream"},
                {".hxk", "application/xml"},
                {".hxq", "application/octet-stream"},
                {".hxr", "application/octet-stream"},
                {".hxs", "application/octet-stream"},
                {".hxt", "text/html"},
                {".hxv", "application/xml"},
                {".hxw", "application/octet-stream"},
                {".hxx", "text/plain"},
                {".i", "text/plain"},
                {".ical", "text/calendar"},
                {".icalendar", "text/calendar"},
                {".ico", "image/x-icon"},
                {".ics", "text/calendar"},
                {".idl", "text/plain"},
                {".ief", "image/ief"},
                {".ifb", "text/calendar"},
                {".iii", "application/x-iphone"},
                {".inc", "text/plain"},
                {".inf", "application/octet-stream"},
                {".ini", "text/plain"},
                {".inl", "text/plain"},
                {".ins", "application/x-internet-signup"},
                {".ipa", "application/x-itunes-ipa"},
                {".ipg", "application/x-itunes-ipg"},
                {".ipproj", "text/plain"},
                {".ipsw", "application/x-itunes-ipsw"},
                {".iqy", "text/x-ms-iqy"},
                {".isp", "application/x-internet-signup"},
                {".isma", "application/octet-stream"},
                {".ismv", "application/octet-stream"},
                {".ite", "application/x-itunes-ite"},
                {".itlp", "application/x-itunes-itlp"},
                {".itms", "application/x-itunes-itms"},
                {".itpc", "application/x-itunes-itpc"},
                {".IVF", "video/x-ivf"},
                {".jar", "application/java-archive"},
                {".java", "application/octet-stream"},
                {".jck", "application/liquidmotion"},
                {".jcz", "application/liquidmotion"},
                {".jfif", "image/pjpeg"},
                {".jnlp", "application/x-java-jnlp-file"},
                {".jpb", "application/octet-stream"},
                {".jpe", "image/jpeg"},
                {".jpeg", "image/jpeg"},
                {".jpg", "image/jpeg"},
                {".js", "application/javascript"},
                {".json", "application/json"},
                {".jsx", "text/jscript"},
                {".jsxbin", "text/plain"},
                {".latex", "application/x-latex"},
                {".library-ms", "application/windows-library+xml"},
                {".lit", "application/x-ms-reader"},
                {".loadtest", "application/xml"},
                {".lpk", "application/octet-stream"},
                {".lsf", "video/x-la-asf"},
                {".lst", "text/plain"},
                {".lsx", "video/x-la-asf"},
                {".lzh", "application/octet-stream"},
                {".m13", "application/x-msmediaview"},
                {".m14", "application/x-msmediaview"},
                {".m1v", "video/mpeg"},
                {".m2t", "video/vnd.dlna.mpeg-tts"},
                {".m2ts", "video/vnd.dlna.mpeg-tts"},
                {".m2v", "video/mpeg"},
                {".m3u", "application/vnd.apple.mpegurl"},
                {".m3u8", "application/vnd.apple.mpegurl"},
                {".m4a", "audio/m4a"},
                {".m4b", "audio/m4b"},
                {".m4p", "audio/m4p"},
                {".m4r", "audio/x-m4r"},
                {".m4v", "video/x-m4v"},
                {".mac", "image/x-macpaint"},
                {".mak", "text/plain"},
                {".man", "application/x-troff-man"},
                {".manifest", "application/x-ms-manifest"},
                {".map", "text/plain"},
                {".master", "application/xml"},
                {".mbox", "application/mbox"},
                {".mda", "application/msaccess"},
                {".mdb", "application/x-msaccess"},
                {".mde", "application/msaccess"},
                {".mdp", "application/octet-stream"},
                {".me", "application/x-troff-me"},
                {".mfp", "application/x-shockwave-flash"},
                {".mht", "message/rfc822"},
                {".mhtml", "message/rfc822"},
                {".mid", "audio/mid"},
                {".midi", "audio/mid"},
                {".mix", "application/octet-stream"},
                {".mk", "text/plain"},
                {".mk3d", "video/x-matroska-3d"},
                {".mka", "audio/x-matroska"},
                {".mkv", "video/x-matroska"},
                {".mmf", "application/x-smaf"},
                {".mno", "text/xml"},
                {".mny", "application/x-msmoney"},
                {".mod", "video/mpeg"},
                {".mov", "video/quicktime"},
                {".movie", "video/x-sgi-movie"},
                {".mp2", "video/mpeg"},
                {".mp2v", "video/mpeg"},
                {".mp3", "audio/mpeg"},
                {".mp4", "video/mp4"},
                {".mp4v", "video/mp4"},
                {".mpa", "video/mpeg"},
                {".mpe", "video/mpeg"},
                {".mpeg", "video/mpeg"},
                {".mpf", "application/vnd.ms-mediapackage"},
                {".mpg", "video/mpeg"},
                {".mpp", "application/vnd.ms-project"},
                {".mpv2", "video/mpeg"},
                {".mqv", "video/quicktime"},
                {".ms", "application/x-troff-ms"},
                {".msg", "application/vnd.ms-outlook"},
                {".msi", "application/octet-stream"},
                {".mso", "application/octet-stream"},
                {".mts", "video/vnd.dlna.mpeg-tts"},
                {".mtx", "application/xml"},
                {".mvb", "application/x-msmediaview"},
                {".mvc", "application/x-miva-compiled"},
                {".mxf", "application/mxf"},
                {".mxp", "application/x-mmxp"},
                {".nc", "application/x-netcdf"},
                {".nsc", "video/x-ms-asf"},
                {".nws", "message/rfc822"},
                {".ocx", "application/octet-stream"},
                {".oda", "application/oda"},
                {".odb", "application/vnd.oasis.opendocument.database"},
                {".odc", "application/vnd.oasis.opendocument.chart"},
                {".odf", "application/vnd.oasis.opendocument.formula"},
                {".odg", "application/vnd.oasis.opendocument.graphics"},
                {".odh", "text/plain"},
                {".odi", "application/vnd.oasis.opendocument.image"},
                {".odl", "text/plain"},
                {".odm", "application/vnd.oasis.opendocument.text-master"},
                {".odp", "application/vnd.oasis.opendocument.presentation"},
                {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
                {".odt", "application/vnd.oasis.opendocument.text"},
                {".oga", "audio/ogg"},
                {".ogg", "audio/ogg"},
                {".ogv", "video/ogg"},
                {".ogx", "application/ogg"},
                {".one", "application/onenote"},
                {".onea", "application/onenote"},
                {".onepkg", "application/onenote"},
                {".onetmp", "application/onenote"},
                {".onetoc", "application/onenote"},
                {".onetoc2", "application/onenote"},
                {".opus", "audio/ogg"},
                {".orderedtest", "application/xml"},
                {".osdx", "application/opensearchdescription+xml"},
                {".otf", "application/font-sfnt"},
                {".otg", "application/vnd.oasis.opendocument.graphics-template"},
                {".oth", "application/vnd.oasis.opendocument.text-web"},
                {".otp", "application/vnd.oasis.opendocument.presentation-template"},
                {".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
                {".ott", "application/vnd.oasis.opendocument.text-template"},
                {".oxt", "application/vnd.openofficeorg.extension"},
                {".p10", "application/pkcs10"},
                {".p12", "application/x-pkcs12"},
                {".p7b", "application/x-pkcs7-certificates"},
                {".p7c", "application/pkcs7-mime"},
                {".p7m", "application/pkcs7-mime"},
                {".p7r", "application/x-pkcs7-certreqresp"},
                {".p7s", "application/pkcs7-signature"},
                {".pbm", "image/x-portable-bitmap"},
                {".pcast", "application/x-podcast"},
                {".pct", "image/pict"},
                {".pcx", "application/octet-stream"},
                {".pcz", "application/octet-stream"},
                {".pdf", "application/pdf"},
                {".pfb", "application/octet-stream"},
                {".pfm", "application/octet-stream"},
                {".pfx", "application/x-pkcs12"},
                {".pgm", "image/x-portable-graymap"},
                {".pic", "image/pict"},
                {".pict", "image/pict"},
                {".pkgdef", "text/plain"},
                {".pkgundef", "text/plain"},
                {".pko", "application/vnd.ms-pki.pko"},
                {".pls", "audio/scpls"},
                {".pma", "application/x-perfmon"},
                {".pmc", "application/x-perfmon"},
                {".pml", "application/x-perfmon"},
                {".pmr", "application/x-perfmon"},
                {".pmw", "application/x-perfmon"},
                {".png", "image/png"},
                {".pnm", "image/x-portable-anymap"},
                {".pnt", "image/x-macpaint"},
                {".pntg", "image/x-macpaint"},
                {".pnz", "image/png"},
                {".pot", "application/vnd.ms-powerpoint"},
                {".potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"},
                {".potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
                {".ppa", "application/vnd.ms-powerpoint"},
                {".ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12"},
                {".ppm", "image/x-portable-pixmap"},
                {".pps", "application/vnd.ms-powerpoint"},
                {".ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
                {".ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
                {".ppt", "application/vnd.ms-powerpoint"},
                {".pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
                {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
                {".prf", "application/pics-rules"},
                {".prm", "application/octet-stream"},
                {".prx", "application/octet-stream"},
                {".ps", "application/postscript"},
                {".psc1", "application/PowerShell"},
                {".psd", "application/octet-stream"},
                {".psess", "application/xml"},
                {".psm", "application/octet-stream"},
                {".psp", "application/octet-stream"},
                {".pst", "application/vnd.ms-outlook"},
                {".pub", "application/x-mspublisher"},
                {".pwz", "application/vnd.ms-powerpoint"},
                {".qht", "text/x-html-insertion"},
                {".qhtm", "text/x-html-insertion"},
                {".qt", "video/quicktime"},
                {".qti", "image/x-quicktime"},
                {".qtif", "image/x-quicktime"},
                {".qtl", "application/x-quicktimeplayer"},
                {".qxd", "application/octet-stream"},
                {".ra", "audio/x-pn-realaudio"},
                {".ram", "audio/x-pn-realaudio"},
                {".rar", "application/x-rar-compressed"},
                {".ras", "image/x-cmu-raster"},
                {".rat", "application/rat-file"},
                {".rc", "text/plain"},
                {".rc2", "text/plain"},
                {".rct", "text/plain"},
                {".rdlc", "application/xml"},
                {".reg", "text/plain"},
                {".resx", "application/xml"},
                {".rf", "image/vnd.rn-realflash"},
                {".rgb", "image/x-rgb"},
                {".rgs", "text/plain"},
                {".rm", "application/vnd.rn-realmedia"},
                {".rmi", "audio/mid"},
                {".rmp", "application/vnd.rn-rn_music_package"},
                {".roff", "application/x-troff"},
                {".rpm", "audio/x-pn-realaudio-plugin"},
                {".rqy", "text/x-ms-rqy"},
                {".rtf", "application/rtf"},
                {".rtx", "text/richtext"},
                {".rvt", "application/octet-stream" },
                {".ruleset", "application/xml"},
                {".s", "text/plain"},
                {".safariextz", "application/x-safari-safariextz"},
                {".scd", "application/x-msschedule"},
                {".scr", "text/plain"},
                {".sct", "text/scriptlet"},
                {".sd2", "audio/x-sd2"},
                {".sdp", "application/sdp"},
                {".sea", "application/octet-stream"},
                {".searchConnector-ms", "application/windows-search-connector+xml"},
                {".setpay", "application/set-payment-initiation"},
                {".setreg", "application/set-registration-initiation"},
                {".settings", "application/xml"},
                {".sgimb", "application/x-sgimb"},
                {".sgml", "text/sgml"},
                {".sh", "application/x-sh"},
                {".shar", "application/x-shar"},
                {".shtml", "text/html"},
                {".sit", "application/x-stuffit"},
                {".sitemap", "application/xml"},
                {".skin", "application/xml"},
                {".skp", "application/x-koan" },
                {".sldm", "application/vnd.ms-powerpoint.slide.macroEnabled.12"},
                {".sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
                {".slk", "application/vnd.ms-excel"},
                {".sln", "text/plain"},
                {".slupkg-ms", "application/x-ms-license"},
                {".smd", "audio/x-smd"},
                {".smi", "application/octet-stream"},
                {".smx", "audio/x-smd"},
                {".smz", "audio/x-smd"},
                {".snd", "audio/basic"},
                {".snippet", "application/xml"},
                {".snp", "application/octet-stream"},
                {".sol", "text/plain"},
                {".sor", "text/plain"},
                {".spc", "application/x-pkcs7-certificates"},
                {".spl", "application/futuresplash"},
                {".spx", "audio/ogg"},
                {".src", "application/x-wais-source"},
                {".srf", "text/plain"},
                {".SSISDeploymentManifest", "text/xml"},
                {".ssm", "application/streamingmedia"},
                {".sst", "application/vnd.ms-pki.certstore"},
                {".stl", "application/vnd.ms-pki.stl"},
                {".sv4cpio", "application/x-sv4cpio"},
                {".sv4crc", "application/x-sv4crc"},
                {".svc", "application/xml"},
                {".svg", "image/svg+xml"},
                {".swf", "application/x-shockwave-flash"},
                {".step", "application/step"},
                {".stp", "application/step"},
                {".t", "application/x-troff"},
                {".tar", "application/x-tar"},
                {".tcl", "application/x-tcl"},
                {".testrunconfig", "application/xml"},
                {".testsettings", "application/xml"},
                {".tex", "application/x-tex"},
                {".texi", "application/x-texinfo"},
                {".texinfo", "application/x-texinfo"},
                {".tgz", "application/x-compressed"},
                {".thmx", "application/vnd.ms-officetheme"},
                {".thn", "application/octet-stream"},
                {".tif", "image/tiff"},
                {".tiff", "image/tiff"},
                {".tlh", "text/plain"},
                {".tli", "text/plain"},
                {".toc", "application/octet-stream"},
                {".tr", "application/x-troff"},
                {".trm", "application/x-msterminal"},
                {".trx", "application/xml"},
                {".ts", "video/vnd.dlna.mpeg-tts"},
                {".tsv", "text/tab-separated-values"},
                {".ttf", "application/font-sfnt"},
                {".tts", "video/vnd.dlna.mpeg-tts"},
                {".txt", "text/plain"},
                {".u32", "application/octet-stream"},
                {".uls", "text/iuls"},
                {".user", "text/plain"},
                {".ustar", "application/x-ustar"},
                {".vb", "text/plain"},
                {".vbdproj", "text/plain"},
                {".vbk", "video/mpeg"},
                {".vbproj", "text/plain"},
                {".vbs", "text/vbscript"},
                {".vcf", "text/x-vcard"},
                {".vcproj", "application/xml"},
                {".vcs", "text/plain"},
                {".vcxproj", "application/xml"},
                {".vddproj", "text/plain"},
                {".vdp", "text/plain"},
                {".vdproj", "text/plain"},
                {".vdx", "application/vnd.ms-visio.viewer"},
                {".vml", "text/xml"},
                {".vscontent", "application/xml"},
                {".vsct", "text/xml"},
                {".vsd", "application/vnd.visio"},
                {".vsi", "application/ms-vsi"},
                {".vsix", "application/vsix"},
                {".vsixlangpack", "text/xml"},
                {".vsixmanifest", "text/xml"},
                {".vsmdi", "application/xml"},
                {".vspscc", "text/plain"},
                {".vss", "application/vnd.visio"},
                {".vsscc", "text/plain"},
                {".vssettings", "text/xml"},
                {".vssscc", "text/plain"},
                {".vst", "application/vnd.visio"},
                {".vstemplate", "text/xml"},
                {".vsto", "application/x-ms-vsto"},
                {".vsw", "application/vnd.visio"},
                {".vsx", "application/vnd.visio"},
                {".vtt", "text/vtt"},
                {".vtx", "application/vnd.visio"},
                {".wasm", "application/wasm"},
                {".wav", "audio/wav"},
                {".wave", "audio/wav"},
                {".wax", "audio/x-ms-wax"},
                {".wbk", "application/msword"},
                {".wbmp", "image/vnd.wap.wbmp"},
                {".wcm", "application/vnd.ms-works"},
                {".wdb", "application/vnd.ms-works"},
                {".wdp", "image/vnd.ms-photo"},
                {".webarchive", "application/x-safari-webarchive"},
                {".webm", "video/webm"},
                {".webp", "image/webp"}, /* https://en.wikipedia.org/wiki/WebP */
                {".webtest", "application/xml"},
                {".wiq", "application/xml"},
                {".wiz", "application/msword"},
                {".wks", "application/vnd.ms-works"},
                {".WLMP", "application/wlmoviemaker"},
                {".wlpginstall", "application/x-wlpg-detect"},
                {".wlpginstall3", "application/x-wlpg3-detect"},
                {".wm", "video/x-ms-wm"},
                {".wma", "audio/x-ms-wma"},
                {".wmd", "application/x-ms-wmd"},
                {".wmf", "application/x-msmetafile"},
                {".wml", "text/vnd.wap.wml"},
                {".wmlc", "application/vnd.wap.wmlc"},
                {".wmls", "text/vnd.wap.wmlscript"},
                {".wmlsc", "application/vnd.wap.wmlscriptc"},
                {".wmp", "video/x-ms-wmp"},
                {".wmv", "video/x-ms-wmv"},
                {".wmx", "video/x-ms-wmx"},
                {".wmz", "application/x-ms-wmz"},
                {".woff", "application/font-woff"},
                {".woff2", "application/font-woff2"},
                {".wpl", "application/vnd.ms-wpl"},
                {".wps", "application/vnd.ms-works"},
                {".wri", "application/x-mswrite"},
                {".wrl", "x-world/x-vrml"},
                {".wrz", "x-world/x-vrml"},
                {".wsc", "text/scriptlet"},
                {".wsdl", "text/xml"},
                {".wvx", "video/x-ms-wvx"},
                {".x", "application/directx"},
                {".xaf", "x-world/x-vrml"},
                {".xaml", "application/xaml+xml"},
                {".xap", "application/x-silverlight-app"},
                {".xbap", "application/x-ms-xbap"},
                {".xbm", "image/x-xbitmap"},
                {".xdr", "text/plain"},
                {".xht", "application/xhtml+xml"},
                {".xhtml", "application/xhtml+xml"},
                {".xla", "application/vnd.ms-excel"},
                {".xlam", "application/vnd.ms-excel.addin.macroEnabled.12"},
                {".xlc", "application/vnd.ms-excel"},
                {".xld", "application/vnd.ms-excel"},
                {".xlk", "application/vnd.ms-excel"},
                {".xll", "application/vnd.ms-excel"},
                {".xlm", "application/vnd.ms-excel"},
                {".xls", "application/vnd.ms-excel"},
                {".xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
                {".xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"},
                {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
                {".xlt", "application/vnd.ms-excel"},
                {".xltm", "application/vnd.ms-excel.template.macroEnabled.12"},
                {".xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
                {".xlw", "application/vnd.ms-excel"},
                {".xml", "text/xml"},
                {".xmp", "application/octet-stream" },
                {".xmta", "application/xml"},
                {".xof", "x-world/x-vrml"},
                {".XOML", "text/plain"},
                {".xpm", "image/x-xpixmap"},
                {".xps", "application/vnd.ms-xpsdocument"},
                {".xrm-ms", "text/xml"},
                {".xsc", "application/xml"},
                {".xsd", "text/xml"},
                {".xsf", "text/xml"},
                {".xsl", "text/xml"},
                {".xslt", "text/xml"},
                {".xsn", "application/octet-stream"},
                {".xss", "application/xml"},
                {".xspf", "application/xspf+xml"},
                {".xtp", "application/octet-stream"},
                {".xwd", "image/x-xwindowdump"},
                {".z", "application/x-compress"},
                {".zip", "application/zip"},

                {"application/fsharp-script", ".fsx"},
                {"application/msaccess", ".adp"},
                {"application/msword", ".doc"},
                {"application/octet-stream", ".bin"},
                {"application/onenote", ".one"},
                {"application/postscript", ".eps"},
                {"application/step", ".step"},
                {"application/vnd.ms-excel", ".xls"},
                {"application/vnd.ms-powerpoint", ".ppt"},
                {"application/vnd.ms-works", ".wks"},
                {"application/vnd.visio", ".vsd"},
                {"application/x-director", ".dir"},
                {"application/x-shockwave-flash", ".swf"},
                {"application/x-x509-ca-cert", ".cer"},
                {"application/x-zip-compressed", ".zip"},
                {"application/xhtml+xml", ".xhtml"},
                {"application/xml", ".xml"},  // anomoly, .xml -> text/xml, but application/xml -> many thingss, but all are xml, so safest is .xml
                {"audio/aac", ".AAC"},
                {"audio/aiff", ".aiff"},
                {"audio/basic", ".snd"},
                {"audio/mid", ".midi"},
                {"audio/wav", ".wav"},
                {"audio/x-m4a", ".m4a"},
                {"application/vnd.apple.mpegurl", ".m3u"},
                {"audio/x-pn-realaudio", ".ra"},
                {"audio/x-smd", ".smd"},
                {"image/bmp", ".bmp"},
                {"image/jpeg", ".jpg"},
                {"image/pict", ".pic"},
                {"image/png", ".png"}, //Defined in [RFC-2045], [RFC-2048]
                {"image/x-png", ".png"}, //See https://www.w3.org/TR/PNG/#A-Media-type :"It is recommended that implementations also recognize the media type "image/x-png"."
                {"image/tiff", ".tiff"},
                {"image/x-macpaint", ".mac"},
                {"image/x-quicktime", ".qti"},
                {"message/rfc822", ".eml"},
                {"text/calendar", ".ics"},
                {"text/html", ".html"},
                {"text/plain", ".txt"},
                {"text/scriptlet", ".wsc"},
                {"text/xml", ".xml"},
                {"video/3gpp", ".3gp"},
                {"video/3gpp2", ".3gp2"},
                {"video/mp4", ".mp4"},
                {"video/mpeg", ".mpg"},
                {"video/quicktime", ".mov"},
                {"video/vnd.dlna.mpeg-tts", ".m2t"},
                {"video/x-dv", ".dv"},
                {"video/x-la-asf", ".lsf"},
                {"video/x-ms-asf", ".asf"},
                {"x-world/x-vrml", ".xof"},

                #endregion

                };

        var cache = mappings.ToList(); // need ToList() to avoid modifying while still enumerating

        foreach (var mapping in cache)
        {
            if (!mappings.ContainsKey(mapping.Value))
            {
                mappings.Add(mapping.Value, mapping.Key);
            }
        }

        return mappings;
    }

    public static string GetMimeType(string extension)
    {
        if (extension == null)
        {
            throw new ArgumentNullException("extension");
        }

        if (!extension.StartsWith("."))
        {
            extension = "." + extension;
        }

        string mime;

        return _mappings.Value.TryGetValue(extension, out mime) ? mime : "application/octet-stream";
    }

    public static string GetExtension(string mimeType)
    {
        return GetExtension(mimeType, true);
    }

    public static string GetExtension(string mimeType, bool throwErrorIfNotFound)
    {
        if (mimeType == null)
        {
            throw new ArgumentNullException("mimeType");
        }

        if (mimeType.StartsWith("."))
        {
            throw new ArgumentException("Requested mime type is not valid: " + mimeType);
        }

        string extension;

        if (_mappings.Value.TryGetValue(mimeType, out extension))
        {
            return extension;
        }
        if (throwErrorIfNotFound)
        {
            throw new ArgumentException("Requested mime type is not registered: " + mimeType);
        }
        else
        {
            return string.Empty;
        }
    }

    #endregion

    #region Random

    public string GetRandomBase32String(int param1)
    {
        Random _loc_1 = new Random(GetSeed());
        string _loc_2 = Base32_Alphabet;
        char[] _loc_3 = new char[param1];
        for (int _loc_4 = 0; _loc_4 < param1; _loc_4++) { _loc_3[_loc_4] = _loc_2[_loc_1.Next(_loc_2.Length)]; }
        return new string(_loc_3);
    }

    public int GetSeed()
    {
        byte[] _loc_1 = new byte[4];
        RNGCryptoServiceProvider _loc_2 = new RNGCryptoServiceProvider();
        _loc_2.GetBytes(_loc_1);
        return System.Math.Abs(BitConverter.ToInt32(_loc_1, 0));
    }

    #endregion

    #region SHA1

    public string SHA1(string param1)
    {
        return SHA1_Bytes(Encoding.UTF8.GetBytes(param1));
    }

    public string SHA1_Bytes(byte[] param1)
    {
        param1 = new SHA1CryptoServiceProvider().ComputeHash(param1);
        string _loc_1 = "";
        foreach (byte _loc_2 in param1) { _loc_1 += _loc_2.ToString("x2"); }
        return _loc_1.ToUpper();
    }

    #endregion

    #region Time

    public long Time()
    {
        return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds;
    }

    #endregion

</Script>