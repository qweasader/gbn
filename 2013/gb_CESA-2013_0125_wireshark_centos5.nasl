# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019123.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881567");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:01 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698",
                "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066",
                "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290",
                "CVE-2012-4291");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2013:0125");
  script_name("CentOS Update for wireshark CESA-2013:0125 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"wireshark on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Wireshark, previously known as Ethereal, is a network protocol analyzer. It
  is used to capture and browse the traffic running on a computer network.

  A heap-based buffer overflow flaw was found in the way Wireshark handled
  Endace ERF (Extensible Record Format) capture files. If Wireshark opened a
  specially-crafted ERF capture file, it could crash or, possibly, execute
  arbitrary code as the user running Wireshark. (CVE-2011-4102)

  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malicious dump file. (CVE-2011-1958, CVE-2011-1959, CVE-2011-2175,
  CVE-2011-2698, CVE-2012-0041, CVE-2012-0042, CVE-2012-0066, CVE-2012-0067,
  CVE-2012-4285, CVE-2012-4289, CVE-2012-4290, CVE-2012-4291)

  The CVE-2011-1958, CVE-2011-1959, CVE-2011-2175, and CVE-2011-4102 issues
  were discovered by Huzaifa Sidhpurwala of the Red Hat Security Response
  Team.

  This update also fixes the following bugs:

  * When Wireshark starts with the X11 protocol being tunneled through an SSH
  connection, it automatically prepares its capture filter to omit the SSH
  packets. If the SSH connection was to a link-local IPv6 address including
  an interface name (for example ssh -X [ipv6addr]%eth0), Wireshark parsed
  this address erroneously, constructed an incorrect capture filter and
  refused to capture packets. The 'Invalid capture filter' message was
  displayed. With this update, parsing of link-local IPv6 addresses is fixed
  and Wireshark correctly prepares a capture filter to omit SSH packets over
  a link-local IPv6 connection. (BZ#438473)

  * Previously, Wireshark's column editing dialog malformed column names when
  they were selected. With this update, the dialog is fixed and no longer
  breaks column names. (BZ#493693)

  * Previously, TShark, the console packet analyzer, did not properly analyze
  the exit code of Dumpcap, Wireshark's packet capturing back end. As a
  result, TShark returned exit code 0 when Dumpcap failed to parse its
  command-line arguments. In this update, TShark correctly propagates the
  Dumpcap exit code and returns a non-zero exit code when Dumpcap fails.
  (BZ#580510)

  * Previously, the TShark '-s' (snapshot length) option worked only for a
  value greater than 68 bytes. If a lower value was specified, TShark
  captured just 68 bytes of incoming packets. With this update, the '-s'
  option is fixed and sizes lower than 68 bytes work as expected. (BZ#580513)

  This update also adds the following enhancement:

  * In ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.15~5.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
