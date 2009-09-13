package Warden;

import util.UnsafeOperations;

public class WardenMemory {
	
	private static final UnsafeOperations unsafe = UnsafeOperations.getUnsafe();

	private long ptrMe = 0;
	private long ptrFunc = 0;
	private long Mem = 0;
	private long Pos = 0;
	
	public WardenMemory()
	{
		
		
		
	}
}
