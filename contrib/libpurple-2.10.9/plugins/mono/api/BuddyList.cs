namespace Purple {
	using System;
	using System.Runtime.CompilerServices;

	public class BuddyList {
		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern private static IntPtr _get_handle();

		private static IntPtr handle = _get_handle();
		
		public static Event OnBuddyStatusChanged =
			new Event(handle, "buddy-status-changed");
		
		public static IntPtr GetHandle()
		{
			return _get_handle();
		}		
	}
}
