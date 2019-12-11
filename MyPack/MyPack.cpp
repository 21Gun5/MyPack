#include "MyPack.h"
#include <DbgHelp.h>
#include <time.h>
#pragma comment(lib,"DbgHelp.lib")

 // 获取PE头相关信息
PIMAGE_DOS_HEADER MyPack::GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS MyPack::GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase +GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER MyPack::GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER MyPack::GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

// 进行文件/内存对齐
DWORD MyPack::Align(DWORD size, DWORD n)
{
	return size / n == 0 ? n : (size / n + 1)*n;
}

//传入文件名,若文件存在且为PE则打开
void MyPack::LoadFile(LPCSTR fileName)
{
	// 1 若文件存在就打开,打开仅为了读取文件数据
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, NULL,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 获取文件大小,并用此大小申请缓冲区
	m_fileSize = GetFileSize(hFile, NULL);
	m_fileBase = (DWORD)calloc(m_fileSize, sizeof(BYTE));//calloc 申请并初始化
	// 3 将文件内容读取到缓冲区
	DWORD readSize = 0;// 实际读取的大小
	ReadFile(hFile, (LPVOID)m_fileBase, m_fileSize, &readSize, NULL);
	// 4 防止句柄泄露,关闭句柄
	CloseHandle(hFile);

	return;
}
void MyPack::LoadStub(LPCSTR fileName)
{
	// 1 以不执行dllMain的方式,加载模块到当前的内存中
	m_dllBase = (DWORD)LoadLibraryExA(fileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// 2 从dll中获取start函数的地址
	DWORD startAddr = (DWORD)GetProcAddress((HMODULE)m_dllBase, "Start");
	// 3 计算start函数的段内偏移,最终地址=加载基址+区段基址+段内偏移
	m_startOffset = startAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
	// 4 获取dll导出的共享接口,通过此接口可实现数据共享(地址间接修改
	m_pShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dllBase, "shareData");//here
	//m_pShareData = (PSubConf)GetProcAddress((HMODULE)m_dllBase, "g_conf");
}

// 后者复制到前者,实现添加新区段
void MyPack::CopySection(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	// 1 获取区段头表最后一个区段头的地址
	auto pLastSection = &IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase))[GetFileHeader(m_fileBase)->NumberOfSections - 1];
	// 2 区段数量+1(文件头中
	GetFileHeader(m_fileBase)->NumberOfSections += 1;
	// 3 通过最后一个区段头,找到新添加区段头的位置,并填充0
	auto pNewSection = pLastSection + 1;
	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	// 4 从dll中获取需拷贝的源区段
	auto srcSection = GetSection(m_dllBase, srcSectionName);
	// 5 直接将源区段的信息拷贝至新/目的区段中(无需设置属性了,只改名字即可
	memcpy(pNewSection, srcSection, sizeof(IMAGE_SECTION_HEADER));
	// 6 设置新区段头的字段:区段名称
	memcpy(pNewSection->Name, dstSectionName, 7);// 用memcpy而非strcpy; 总共8字节,拷贝7,预留一个给\0
	// 7 设置新区段所在RVA = 上一个区段RVA　+ 其对齐后的内存大小
	pNewSection->VirtualAddress = pLastSection->VirtualAddress + Align(pLastSection->Misc.VirtualSize, GetOptHeader(m_fileBase)->SectionAlignment);
	// 8 设置新区段所在FOA = 上一个区段FOA + 其对齐后的文件大小
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + Align(pLastSection->SizeOfRawData, GetOptHeader(m_fileBase)->FileAlignment);
	// 9 设置新区段的文件大小和内存大小(二者相等即可
	//pNewSection->SizeOfRawData = pNewSection->Misc.VirtualSize = 0x200;
	// 10 重新计算文件的物理大小= 最后一个区段FOA + 其文件大小,并将原文件数据保存起来
	m_fileSize = pNewSection->PointerToRawData + pNewSection->SizeOfRawData;
	m_fileBase = (DWORD)realloc((void *)m_fileBase, m_fileSize);// 之所以用allco而非new,就是为了后面可以用realloc
	// 11 修改文件的内存大小 = 最后一个区段RVA + 其内存大小
	GetOptHeader(m_fileBase)->SizeOfImage = pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize;
	
	return;
}

// 将添加区段后的文件另存为新文件
void MyPack::SaveFile(LPCSTR fileName)
{
	// 1 创建文件,获取句柄(写文件/无论存在与否均创建
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 将内存中的文件数据写入新文件中
	DWORD writeSize = 0;// 实际写入大小
	WriteFile(hFile, (LPVOID *)m_fileBase, m_fileSize, &writeSize, NULL);
	// 关闭文件句柄以防止泄露
	CloseHandle(hFile);

	return;
}

// 获取区段头信息(区段头结构体
PIMAGE_SECTION_HEADER MyPack::GetSection(DWORD fileBase, LPCSTR sectionName)
{
	// 1 获取区段头表(即第一项)
	auto sectionTable = IMAGE_FIRST_SECTION(GetNtHeader(fileBase));
	// 2 获取区段头表的元素个数
	WORD sectionNumber = GetFileHeader(fileBase)->NumberOfSections;
	// 3 遍历区段头表,比较其名称,返回区段头所在地址(而非真正区段
	for (int i = 0; i < sectionNumber; i++)
	{
		// 4 用memcpy而非strcmp,前者可指定比较长度,后者以\0为准
		if (!memcmp(sectionName, sectionTable[i].Name, strlen(sectionName) + 1))
			return &sectionTable[i];
	}
	// 5 若未找到,则返回null
	return NULL;
}

// 重新设置OEP
void MyPack::SetOEP()
{
	// 1 修改OEP前,将原始OEP保存下来(可共享给dll,本质是通过地址间接修改
	m_pShareData->origOEP = GetOptHeader(m_fileBase)->AddressOfEntryPoint;//here
	//m_pShareData->srcOep = GetOptHeader(m_fileBase)->AddressOfEntryPoint;
	// 2 设置扩展头中OEP字段, 新OEP= start 段内偏移+新区段基址
	GetOptHeader(m_fileBase)->AddressOfEntryPoint = m_startOffset + GetSection(m_fileBase, ".pack")->VirtualAddress;
	return;
}

// 设置新区段内容(后者拷贝至前者
void MyPack::CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	// 1 获取源区段在虚拟空间中的地址(映像,LoadLibrary获取的
	BYTE * pSrcData = (BYTE *)(GetSection(m_dllBase,".text")->VirtualAddress + m_dllBase);
	// 2 获取目的区段在物理空间中的地址(镜像,ReadFile获取的
	BYTE * pDstData = (BYTE *)(GetSection(m_fileBase, ".pack")->PointerToRawData + m_fileBase);
	// 3 源映像拷贝至目的镜像
	memcpy(pDstData, pSrcData, GetSection(m_dllBase, ".text")->SizeOfRawData);

	return;
}

// 修复dll壳代码需要重定位的地方
void MyPack::FixDllReloc()
{
	DWORD size = 0, oldProtect = 0;
	// 1 获取dll的重定位表
	auto pRelocTable = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData((LPVOID)m_dllBase, TRUE, 5, &size);
	// 2 循环,直至为0重定位块结束
	while (pRelocTable->SizeOfBlock)
	{
		// 3 若需要重定位的数据在代码段,则修改其访问属性(页为单位0x1000,
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + m_dllBase), 0x1000, PAGE_READWRITE, &oldProtect);
		// 4 获取重定位项数组的首地址 及重定位项的数量
		TypeOffset * pRelocItem = (TypeOffset *)pRelocTable + 1;//+1 跳过重定位结构体
		int relocItemCount = (pRelocTable->SizeOfBlock - 8) / 2;
		// 5 遍历当前重定位块中所有的重定位项
		for (int i = 0; i < relocItemCount; i++)
		{
			// 6 type==3表示需要进行重定位,其他不管
			if (pRelocItem[i].Type == 3)
			{
				// 7 获取需要进行重定位的地址所在的位置
				DWORD * pAddr = (DWORD *)(m_dllBase + pRelocTable->VirtualAddress + pRelocItem[i].Offset);
				// 8 计算出不变的段内偏移=最终地址 - dll 文件加载基址 - .text 区段基址
				DWORD offsetInSection = *pAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
				// 9 修复地址,新地址 = 段内偏移+ exe 文件加载基址 + 新区段.pack基址
				*pAddr = offsetInSection + GetOptHeader(m_fileBase)->ImageBase + GetSection(m_fileBase, ".pack")->VirtualAddress;
			}
		}
		// 10 还原区段的保护属性
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + m_dllBase), 0x1000, oldProtect, &oldProtect);
		// 11 下一个重定位块
		pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTable + pRelocTable->SizeOfBlock);
	}
	// 12 关闭源程序的重定位,上述仅修复了dll壳代码重定位,并非表示源程序支持重定位
	GetOptHeader(m_fileBase)->DllCharacteristics = 0x8100;

	return;
}

// 加密区段(异或加密//here
void MyPack::EncodeSection(LPCSTR sectionName)
{
	// 1 需要加密的区段(源程序代码段
	auto pSection = GetSection(m_fileBase, ".text");
	// 2 区段内容所在的位置
	BYTE * pSectionData = (BYTE*)pSection->PointerToRawData + m_fileBase;
	// 3 解密时需要的信息(共享给dll壳代码
	srand((unsigned int)time(0));
	m_pShareData->key = rand() % 0xff;
	m_pShareData->rva = pSection->VirtualAddress;
	m_pShareData->size = pSection->SizeOfRawData;
	// 4 循环,逐位进行异或加密
	for (int i = 0; i < m_pShareData->size; i++)
	{
		pSectionData[i] ^= m_pShareData->key;
	}
	return;
}
