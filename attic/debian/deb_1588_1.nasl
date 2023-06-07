# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61103");
  script_cve_id("CVE-2007-6712", "CVE-2008-1615", "CVE-2008-2136", "CVE-2008-2137");
  script_tag(name:"creation_date", value:"2008-06-11 16:37:44 +0000 (Wed, 11 Jun 2008)");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1588-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1588-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1588");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels linux-2.6 user-mode-linux' package(s) announced via the DSA-1588-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1588)' (OID: 1.3.6.1.4.1.25623.1.0.61105).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6712

Johannes Bauer discovered an integer overflow condition in the hrtimer subsystem on 64-bit systems. This can be exploited by local users to trigger a denial of service (DoS) by causing the kernel to execute an infinite loop.

CVE-2008-1615

Jan Kratochvil reported a local denial of service condition that permits local users on systems running the amd64 flavor kernel to cause a system crash.

CVE-2008-2136

Paul Harks discovered a memory leak in the Simple Internet Transition (SIT) code used for IPv6 over IPv4 tunnels. This can be exploited by remote users to cause a denial of service condition.

CVE-2008-2137

David Miller and Jan Lieskovsky discovered issues with the virtual address range checking of mmaped regions on the sparc architecture that may be exploited by local users to cause a denial of service.

For the stable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-18etch5.

Builds for linux-2.6/s390 and fai-kernels/powerpc were not yet available at the time of this advisory. This advisory will be updated as these builds become available.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'fai-kernels linux-2.6 user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);