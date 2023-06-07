if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126304");
  script_version("2023-05-18T09:08:59+0000");
  script_tag(name:"last_modification", value:"2023-05-18 09:08:59 +0000 (Thu, 18 May 2023)");
  script_tag(name:"creation_date", value:"2023-01-23 12:50:47 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-0101");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.15.8, 10.0.x < 10.4.2 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Privilege escalation");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a privilege escalation vulnerability.

  This VT has been replaced by the VT 'gb_tns-2023-01 and gb_tns-2023-02'
  (OID: 1.3.6.1.4.1.25623.1.0.126339 and 1.3.6.1.4.1.25623.1.0.126340).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated attacker could potentially execute a specially
  crafted file to obtain root or NT AUTHORITY / SYSTEM privileges on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus versions prior to 8.15.8 and 10.0.x prior to 10.4.2.");

  script_tag(name:"solution", value:"Update to version 8.15.8, 10.4.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-01");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-02");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);