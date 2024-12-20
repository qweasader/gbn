# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871505");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-11-20 06:27:02 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:52:00 +0000 (Tue, 17 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for chrony RHSA-2015:2241-03");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The chrony suite, chronyd and chronyc, is
an advanced implementation of the Network Time Protocol (NTP), specially designed
to support systems with intermittent connections. It can synchronize the system
clock with NTP servers, hardware reference clocks, and manual input. It can also
operate as an NTPv4 (RFC 5905) server or peer to provide a time service to other
computers in the network.

An out-of-bounds write flaw was found in the way chrony stored certain
addresses when configuring NTP or cmdmon access. An attacker that has the
command key and is allowed to access cmdmon (only localhost is allowed by
default) could use this flaw to crash chronyd or, possibly, execute
arbitrary code with the privileges of the chronyd process. (CVE-2015-1821)

An uninitialized pointer use flaw was found when allocating memory to save
unacknowledged replies to authenticated command requests. An attacker that
has the command key and is allowed to access cmdmon (only localhost is
allowed by default) could use this flaw to crash chronyd or, possibly,
execute arbitrary code with the privileges of the chronyd process.
(CVE-2015-1822)

A denial of service flaw was found in the way chrony hosts that were
peering with each other authenticated themselves before updating their
internal state variables. An attacker could send packets to one peer host,
which could cascade to other peers, and stop the synchronization process
among the reached peers. (CVE-2015-1853)

These issues were discovered by Miroslav Lichvar of Red Hat.

The chrony packages have been upgraded to upstream version 2.1.1, which
provides a number of bug fixes and enhancements over the previous version.
Notable enhancements include:

  * Updated to NTP version 4 (RFC 5905)

  * Added pool directive to specify pool of NTP servers

  * Added leapsecmode directive to select how to correct clock for leap
second

  * Added smoothtime directive to smooth served time and enable leap smear

  * Added asynchronous name resolving with POSIX threads

  * Ready for year 2036 (next NTP era)

  * Improved clock control

  * Networking code reworked to open separate client sockets for each NTP
server

(BZ#1117882)

This update also fixes the following bug:

  * The chronyd service previously assumed that network interfaces specified
with the 'bindaddress' directive were ready when the service was started.
This could cause chronyd to fail to bind an NTP server socket to the
interface if the interface was not ready. With this update, chronyd uses
the IP_FREEBIND socket option, enabling it to bind to an interface later,
not only when the service starts. (BZ#11693 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"chrony on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2241-03");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00035.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"chrony", rpm:"chrony~2.1.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~2.1.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
