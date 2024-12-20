# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:168");
  script_oid("1.3.6.1.4.1.25623.1.0.831748");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-23 09:29:43 +0530 (Tue, 23 Oct 2012)");
  script_cve_id("CVE-2012-2389", "CVE-2012-4445");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"MDVSA", value:"2012:168");
  script_name("Mandriva Update for hostapd MDVSA-2012:168 (hostapd)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostapd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"hostapd on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in hostapd:

  hostapd 0.7.3, and possibly other versions before 1.0, uses 0644
  permissions for /etc/hostapd/hostapd.conf, which might allow
  local users to obtain sensitive information such as credentials
  (CVE-2012-2389).

  Heap-based buffer overflow in the eap_server_tls_process_fragment
  function in eap_server_tls_common.c in the EAP authentication server
  in hostapd 0.6 through 1.0 allows remote attackers to cause a denial
  of service (crash or abort) via a small TLS Message Length value in
  an EAP-TLS message with the More Fragments flag set (CVE-2012-4445).

  The updated packages have been patched to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"hostapd", rpm:"hostapd~0.7.3~2.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
