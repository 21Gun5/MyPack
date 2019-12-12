#include <windows.h>
#include "CMyPack.h"

int main()
{
	CMyPack pack;
	pack.LoadFile("demo.exe");
	pack.LoadStub1("MyStub.dll");
	pack.Encrypt();
	pack.ClearDataDir();
	pack.AddSection(".pack",".text");
	pack.FixStubRelocation();
	pack.SetOEP();
	pack.CopySectionData(".pack", ".text");
	pack.CancelRandomBase();
	pack.SaveFile("demo_pack.exe");
	return 0;
}