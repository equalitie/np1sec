using Purple;

public class MPlugin : Plugin
{
	private static PluginInfo info = new PluginInfo("mono-mplugin", "C# Plugin", "0.1", "Test C# Plugin", "Longer Description", "Eoin Coffey", "urled");

	public MPlugin()
		: base(info)
	{
	}

	public void HandleSig(object[] args)
	{
		Buddy buddy = (Buddy)args[0];
		Status old_status = (Status)args[1];
		Status status = (Status)args[2];
		
		Debug.debug(Debug.INFO, "mplug", "buddy " + buddy.Name + " went from " + old_status.Id + " to " + status.Id + "\n");
	}
	
	public override void Load()
	{
		Debug.debug(Debug.INFO, "mplug", "loading...\n");
		
		/*Signal.connect(BuddyList.GetHandle(), this, "buddy-away", new Signal.Handler(HandleSig));*/
		BuddyList.OnBuddyStatusChanged.connect(this, new Signal.Handler(HandleSig));
	}
	
	public override void Unload()
	{
		Debug.debug(Debug.INFO, "mplug", "unloading...\n");
	}
	
	public override void Destroy()
	{
		Debug.debug(Debug.INFO, "mplug", "destroying...\n");
	}
}
