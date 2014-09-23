using System;
using System.Runtime.CompilerServices;

namespace Purple
{
	public class Signal
	{
		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern private static int _connect(IntPtr handle, object plugin, string signal, object evnt);
		
		public delegate void Handler(object[] args);
		
		public static int connect(IntPtr handle, object plugin, string signal, object evnt)
		{
			return _connect(handle, plugin, signal, evnt);
		}
	}
}
