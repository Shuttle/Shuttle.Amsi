using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Shuttle.Amsi
{
    internal static class AmsiNativeMethods
    {
        [DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName,
            out IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("Amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("Amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("Amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanString(IntPtr amsiContext,
            [In] [MarshalAs(UnmanagedType.LPWStr)] string @string,
            [In] [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out int result);

        [DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName,
            IntPtr session, out int result);
    }

    public class AmsiContext : IDisposable
    {
        // See https://msdn.microsoft.com/en-us/library/windows/desktop/dn889584(v=vs.85).aspx
        private const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384;
        private const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479;
        private const int AMSI_RESULT_DETECTED = 32768;

        private const string EicarTestString = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        private readonly IntPtr _context = IntPtr.Zero;

        public AmsiContext(string applicationName = null)
        {
            var nativeCallResult = AmsiNativeMethods.AmsiInitialize(
                string.IsNullOrWhiteSpace(applicationName) ? Guid.NewGuid().ToString() : applicationName, out _context);

            if (nativeCallResult != 0)
            {
                throw new ApplicationException(
                    $"Failed to open an AMSI Session.  Result return was {nativeCallResult}.");
            }
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        public bool IsAvailable()
        {
            int nativeCallResult;
            int scanResult;

            try
            {
                nativeCallResult =
                    AmsiNativeMethods.AmsiScanString(_context, EicarTestString, "EICAR", OpenSession(), out scanResult);
            }
            catch
            {
                return false;
            }

            return nativeCallResult == 0 && HasVirus(scanResult);
        }

        public bool HasMalware(Stream stream, string contentName)
        {
            if (stream == null)
            {
                throw new ArgumentException($"Argument '{nameof(stream)}' may not be null.");
            }

            var position = stream.Position;

            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);

                if (stream.CanSeek)
                {
                    stream.Position = position;
                }

                return HasMalware(ms.ToArray(), contentName);
            }
        }

        public bool HasMalware(byte[] bytearray, string contentName)
        {
            if (bytearray == null)
            {
                throw new ArgumentException($"Argument '{nameof(bytearray)}' may not be null.");
            }

            if (string.IsNullOrWhiteSpace(contentName))
            {
                throw new ArgumentException($"Argument '{nameof(contentName)}' may not be empty.");
            }

            if (bytearray.Length == 0)
            {
                return false;
            }

            var session = IntPtr.Zero;

            try
            {
                session = OpenSession();

                var scanResult = Scan(bytearray, contentName, session);

                return HasVirus(scanResult);
            }
            finally
            {
                if (session != IntPtr.Zero)
                {
                    AmsiNativeMethods.AmsiCloseSession(_context, session);
                }
            }
        }

        private static bool HasVirus(int scanResult)
        {
            if (scanResult >= AMSI_RESULT_DETECTED)
            {
                return true;
            }

            if (scanResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && scanResult <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)
            {
                throw new ApplicationException(
                    $"The admin policy on this machine does not allow virus scanning.  The value returned was {scanResult}.  See https://msdn.microsoft.com/en-us/library/windows/desktop/dn889584(v=vs.85).aspx");
            }

            return false;
        }

        private int Scan(byte[] bytearray, string contentName, IntPtr session)
        {
            int nativeCallResult;
            var length = Convert.ToUInt32(bytearray.Length);
            int scanResult;

            try
            {
                nativeCallResult = AmsiNativeMethods.AmsiScanBuffer(_context, bytearray, length, contentName, session,  out scanResult);
            }
            catch (Exception ex)
            {
                throw new ApplicationException(
                    $"An unexpected error occurred calling AmsiScanBuffer: {ex.Message}. See the inner exception for more details.", ex);
            }

            if (nativeCallResult != 0)
            {
                throw new ApplicationException(
                    $"Failed to scan {contentName}. The call to AmsiScanBuffer returned {nativeCallResult}.");
            }

            return scanResult;
        }

        private IntPtr OpenSession()
        {
            IntPtr session;
            int nativeCallResult;

            try
            {
                nativeCallResult = AmsiNativeMethods.AmsiOpenSession(_context, out session);
            }
            catch (Exception ex)
            {
                throw new ApplicationException(
                    $"Failed to open an AMSI Session: {ex.Message}. See the inner exception for details.", ex);
            }

            if (nativeCallResult != 0)
            {
                throw new ApplicationException(
                    $"Failed to open an AMSI Session.  The OpenSession call returned {nativeCallResult}.");
            }

            return session;
        }

        private void ReleaseUnmanagedResources()
        {
            try
            {
                if (_context != IntPtr.Zero)
                {
                    AmsiNativeMethods.AmsiUninitialize(_context);
                }
            }
            catch
            {
                // ignore
            }
        }

        ~AmsiContext()
        {
            ReleaseUnmanagedResources();
        }
    }
}