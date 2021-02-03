rule goldenspy
{
	meta:
		description = "detects variants of GoldenSpy Malware"

	strings:
		$str01 = {c78510ffffff00000000 c78514ffffff0f000000 c68500ffffff00 c78528ffffff00000000 c7852cffffff0f000000 c68518ffffff00 c78540ffffff00000000 c78544ffffff0f000000 c68530ffffff00 c645fc14 80bd04feffff00}
		$str02 = "Ryeol HTTP Client Class" ascii
		$str03 = "----RYEOL-FB3B405B7EAE495aB0C0295C54D4E096-" ascii
		$str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fwkp.exe" ascii
		$str05 = "svmm" ascii
		$str06 = "PROTOCOL_" ascii
		$str07 = "softList" ascii
		$str08 = "excuteExe" ascii

	condition:
	 	 (uint16(0) == 0x5A4D) and 5 of ($str*)
}
