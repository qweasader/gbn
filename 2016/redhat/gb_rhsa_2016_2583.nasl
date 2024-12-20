# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871685");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-04 05:41:24 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5196", "CVE-2015-5219",
                "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702",
                "CVE-2015-7703", "CVE-2015-7852", "CVE-2015-7974", "CVE-2015-7977",
                "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8158", "CVE-2014-9750");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 17:42:00 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ntp RHSA-2016:2583-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to
synchronize a computer's time with another referenced time source. These packages
include the ntpd service which continuously adjusts system time and utilities used
to query and configure the ntpd service.

Security Fix(es):

  * It was found that the fix for CVE-2014-9750 was incomplete: three issues
were found in the value length checks in NTP's ntp_crypto.c, where a packet
with particular autokey operations that contained malicious data was not
always being completely validated. A remote attacker could use a specially
crafted NTP packet to crash ntpd. (CVE-2015-7691, CVE-2015-7692,
CVE-2015-7702)

  * A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd was
configured to use autokey authentication, an attacker could send packets to
ntpd that would, after several days of ongoing attack, cause it to run out
of memory. (CVE-2015-7701)

  * An off-by-one flaw, leading to a buffer overflow, was found in
cookedprint functionality of ntpq. A specially crafted NTP packet could
potentially cause ntpq to crash. (CVE-2015-7852)

  * A NULL pointer dereference flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large amount
of entries. A remote attacker could potentially use this flaw to crash
ntpd. (CVE-2015-7977)

  * A stack-based buffer overflow flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large amount
of entries. A remote attacker could use this flaw to crash ntpd.
(CVE-2015-7978)

  * It was found that when NTP was configured in broadcast mode, a remote
attacker could broadcast packets with bad authentication to all clients.
The clients, upon receiving the malformed packets, would break the
association with the broadcast server, causing them to become out of sync
over a longer period of time. (CVE-2015-7979)

  * It was found that ntpd could crash due to an uninitialized variable when
processing malformed logconfig configuration commands. (CVE-2015-5194)

  * It was found that ntpd would exit with a segmentation fault when a
statistics type that was not enabled during compilation (e.g. timingstats)
was referenced by the statistics or filegen configuration command.
(CVE-2015-5195)

  * It was found that NTP's :config command could be used to set the pidfile
and driftfile paths without any restrictions. A remote attacker could use
this flaw to overwrite a file on the file system with a file containing the
pid of the ntpd process (immediately) or the current estimated drift of the
system clock (in hourly intervals). (CVE-2015-5196, CVE ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ntp on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2583-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00019.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
