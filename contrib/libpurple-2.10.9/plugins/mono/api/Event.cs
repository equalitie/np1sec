using System;

namespace Purple
{
	public class Event
	{
		private IntPtr handle;
		private string signal;
		
		public Event(IntPtr h, string s)
		{
			handle = h;
			signal = s;
		}
	
		public void connect(object plugin, Signal.Handler handler)
		{
			Signal.connect(handle, plugin, signal, handler);
		}
	}
}
