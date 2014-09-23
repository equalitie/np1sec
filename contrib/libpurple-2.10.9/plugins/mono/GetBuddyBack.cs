using Purple;

public class GetBuddyBack : Plugin
{
	private static PluginInfo info = new PluginInfo("mono-buddyback", "C# Get Buddy Back", "0.1", "Prints when a Buddy returns", "Longer Description", "Eoin Coffey", "urled");

	public GetBuddyBack()
		: base (info)
	{
	}

	public void HandleSig(object[] args)
	{
		Buddy buddy = (Buddy)args[0];
		
		Debug.debug(Debug.INFO, "buddyback", "buddy " + buddy.Name + " is back!\n");
	}
	
	public override void Load()
	{
		Debug.debug(Debug.INFO, "buddyback", "loading...\n");
		
		/*Signal.connect(BuddyList.GetHandle(), this, "buddy-back", new Signal.Handler(HandleSig));*/
		BuddyList.OnBuddyStatusChanged.connect(this, new Signal.Handler(HandleSig));
	}
	
	public override void Unload()
	{
	}
	
	public override void Destroy()
	{
	}
}
