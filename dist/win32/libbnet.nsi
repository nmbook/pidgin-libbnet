;NSIS pidgin-libbnet-0.9.0-winnt

;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"

;--------------------------------
;General

  ;Name and file
  Name "Battle.net Protocol for Pidgin"
  OutFile "out\pidgin-libbnet-1.1.0.exe"

  ;Default installation folder
  InstallDir "$PROGRAMFILES\Pidgin"

  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\pidgin\libbnet" ""

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin
  
  BrandingText "pidgin-libbnet-1.1.0"

;--------------------------------
;Interface Settings

  !define MUI_ICON res\bnet.ico
  
  !define MUI_HEADERIMAGE
  !define MUI_HEADERIMAGE_BITMAP res\header.bmp
  !define MUI_WELCOMEFINISHPAGE_BITMAP res\left.bmp
  
  !define MUI_FINISHPAGE_NOAUTOCLOSE
  !define MUI_UNFINISHPAGE_NOAUTOCLOSE
  
  !define MUI_ABORTWARNING

;--------------------------------
;Page Settings

  !define MUI_DIRECTORYPAGE_TEXT_TOP "Setup will install the Battle.net Protocol for Pidgin in the following folder. This must be equivalent to Pidgin's install folder. If Pidgin is in a different folder, click Browse and locate it. Click Install to start the installation."
  !define MUI_DIRECTORYPAGE_TEXT_DESTINATION "Pidgin's Install Folder"
  
  !define MUI_FINISHPAGE_TEXT "The Battle.net Protocol for Pidgin has been installed on your computer.$\r$\n$\r$\nYou must restart Pidgin in order for Pidgin to recognize the plugin.$\r$\n$\r$\nClick Finish to close this wizard."
  
  !define MUI_FINISHPAGE_NOREBOOTSUPPORT

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE res\LICENSE
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH

  !insertmacro MUI_UNPAGE_WELCOME
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

Section "-libbnet" SecLibbnet

  SetOutPath "$INSTDIR"
  
  IfFileExists "$INSTDIR\pidgin.exe" PidginInstalled
    
    AbortNotInstalled:
    MessageBox MB_ICONSTOP "Pidgin could not be found in $\"$INSTDIR$\". Install Pidgin or select the correct location where it is installed, then try again. The installer has stopped."
    
    DetailPrint "Pidgin could not be found in $\"$INSTDIR$\"."
    DetailPrint "Install Pidgin or select the correct location where it is installed, then try again."
    DetailPrint "The installer has stopped."
    Abort

  PidginInstalled:

  CheckPidginOpen:
    Delete "plugins\libbnet.dll"
    Delete "libgmp-3.dll"
    Delete "libgmp-10.dll"
    
    IfErrors PidginOpen
      Goto CreateAndContinue
  
  PidginOpen:
  
    MessageBox MB_RETRYCANCEL "The installer cannot update the plugin because Pidgin is currently open. Close Pidgin and press Retry." IDRETRY CheckPidginOpen IDCANCEL AbortCurrentlyOpen
    
    AbortCurrentlyOpen:
      DetailPrint "The installer cannot update the plugin because Pidgin is currently open."
      DetailPrint "You cancelled the operation."
      DetailPrint "The installer has stopped."
      Abort
      
  CreateAndContinue:
  
  ;Store installation folder
  WriteRegStr HKCU "    Software\pidgin\libbnet" "" $INSTDIR
  
  ;save libbnet.dll
  File "/oname=plugins\libbnet.dll" in\plugins\libbnet.dll
  
  ;save libgmp-3.dll
  File "/oname=libgmp-3.dll" in\libgmp-3.dll
  
  ;save pixmaps
  File "/oname=pixmaps\pidgin\protocols\16\bnet.png" in\pixmaps\pidgin\protocols\16\bnet.png
  File "/oname=pixmaps\pidgin\protocols\22\bnet.png" in\pixmaps\pidgin\protocols\22\bnet.png
  File "/oname=pixmaps\pidgin\protocols\48\bnet.png" in\pixmaps\pidgin\protocols\48\bnet.png
  
  ;CreateDirectory "libbnet"
  ;Create uninstaller
  ;WriteUninstaller "libbnet\Uninstall.exe"

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  ;LangString DESC_SecLibbnet ${LANG_ENGLISH} "This installs the plugin and related protocol icons."

  ;Assign language strings to sections
  ;!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  ;  !insertmacro MUI_DESCRIPTION_TEXT ${SecLibbnet} $(DESC_SecLibbnet)
  ;!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  SetOutPath "$INSTDIR\.."

  Delete "plugins\libbnet.dll"
  
  Delete "libgmp-3.dll"
  Delete "libgmp-10.dll"
  
  Delete "pixmaps\pidgin\protocols\16\bnet.png"
  Delete "pixmaps\pidgin\protocols\22\bnet.png"
  Delete "pixmaps\pidgin\protocols\48\bnet.png"

  Delete "libbnet\Uninstall.exe"

  RMDir "libbnet"

  DeleteRegKey /ifempty HKCU "Software\pidgin\libbnet"

SectionEnd
