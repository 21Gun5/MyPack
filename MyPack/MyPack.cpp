#include "MyPack.h"
 

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

// 为PE文件添加新区段
void MyPack::AddSection(LPCSTR sectionName)
{
	// 1 获取区段表最后一个区段头的地址
	auto pLastSection = &IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase))[GetFileHeader(m_fileBase)->NumberOfSections - 1];
	// 2 将区段数量+1(文件头中
	GetFileHeader(m_fileBase)->NumberOfSections += 1;
	// 3 通过最后一个区段头,找到新添加区段头的位置,并填充0
	auto pNewSection = pLastSection + 1;
	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	// 4 设置新区段头的字段:区段名称
	memcpy(pNewSection->Name, sectionName, 7);// 用memcpy而非strcpy; 总共8字节,拷贝7,预留一个给\0
	// 5 设置新区段头的字段:区段属性
	pNewSection->Characteristics = 0xE00000E0;// 此时一定包括读/写/执行权限
	// 6 设置新区段所在RVA = 上一个区段RVA　+ 其对齐后的内存大小
	pNewSection->VirtualAddress = pLastSection->VirtualAddress + Align(pLastSection->Misc.VirtualSize, GetOptHeader(m_fileBase)->SectionAlignment);
	// 7 设置新区段所在FOA = 上一个区段FOA + 其对齐后的文件大小
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + Align(pLastSection->SizeOfRawData, GetOptHeader(m_fileBase)->FileAlignment);
	// 8 设置新区段的文件大小和内存大小(二者相等即可
	pNewSection->SizeOfRawData = pNewSection->Misc.VirtualSize = 0x200;
	// 9 重新计算文件的物理大小= 最后一个区段FOA + 其文件大小,并将原文件数据保存起来
	m_fileSize = pNewSection->PointerToRawData + pNewSection->SizeOfRawData;
	m_fileBase = (DWORD)realloc((void *)m_fileBase, m_fileSize);// 之所以用allco而非new,就是为了后面可以用realloc
	// 10 修改文件的内存大小 = 最后一个区段RVA + 其内存大小
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
