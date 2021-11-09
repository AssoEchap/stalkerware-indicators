rule snoopza : stalkerware {
    meta:
        author = "Tek"
        email = "tek@randhome.io"

    strings:
        $s1 = "Server changed to " ascii
        $s2 = "snoopza.com" ascii
        $s3 = "Sim Update imsi:" ascii
        $s4 = "U5t8444cbWHTWgYtCtQE6PkPdteUIOVi" ascii
        $s5 = "jTfELCG992ee6YounW5MV7vsYtzseOp7" ascii
        $s6 = "getSimOperator" ascii
        $s7 = "install error: not exist " ascii
        $s8 = "MIPKOMONITOR" ascii
        $s9 = "3t2PYOBHw5QQ3MraExQvUA==" ascii


    condition:
        uint16(0) == 0x6564 and 7 of them
}

rule mspy : stalkerware {
    meta:
        author = "Tek"
        email = "tek@randhome.io"

    strings:
        $s1 = "mspy_keyboard_used" ascii
        $s2 = "multipart/form-data; boundary=+-=+-=-------+-=+-=" ascii
        $s3 = "mspyonline.com" ascii
        $s4 = "inputType=0x%08x%s%s%s%s%s" ascii
        $s6 = "/proc/%d/oom_score_adj" ascii
        $s7 = "/trackActiveViewUnit" ascii
        $s8 = "InstagramMessageItem" ascii
        $s9 = "KikMessageItem" ascii

    condition:
        uint16(0) == 0x6564 and 5 of them
}

rule spyhide {
    meta:
        author = "Tek"
        email = "tek@randhome.io"

    strings:
        $s1 = "go_to_spyhide" ascii
        $s2 = "configure_hide" ascii
        $s3 = "cellphone-remote-tracker.com" ascii
        $s4 = "bi dont know!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ascii
        $s5 = "bmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm" ascii
        $s6 = "mojmadah@gmail.com" ascii
        $s7 = "www.virsis.net/client" ascii
        $s8 = "Gray_Dolphin" ascii
        $s9 = "new messageeeeeeeeeeeee= " ascii
        $s10 = "@number OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOout" ascii


    condition:
        uint16(0) == 0x6564 and 8 of them
}

rule onetopspy : stalkerware {
    meta:
        author = "Tek"
        email = "tek@randhome.io"

    strings:
        $s1 = "spy-call-active" ascii
        $s2 = "/BackupEmail/" ascii
        $s3 = "G_IS_WHATSAPP_INSTALLED" ascii
        $s4 = "G_LIST_RECORD_CALL_NUMBER" ascii
        $s5 = "1topspy.com" ascii
        $s6 = "duplicate key: " ascii
        $s7 = "setFacebookActive" ascii
        $s8 = "busybox rm -rf " ascii
        $s9 = "Unknown cmd: " ascii
        $s10 = "Testing A ton of commands" ascii
        $s11 = "PATH_BACKUP_FILE_SMS" ascii

    condition:
        uint16(0) == 0x6564 and 9 of them
}

rule ikeymonitor : stalkerware {
    meta:
        author = "Jo Coscia"

    strings:
        $s1 = "emcpanel.com" nocase ascii
        $s2 = "Keylogger_Xposed" ascii
	$s3 = "iKeyMonitor" nocase ascii
	$s4 = "Reg_LKConnotbE" ascii
    condition:
        uint16(0) == 0x6564 and 4 of them
}
