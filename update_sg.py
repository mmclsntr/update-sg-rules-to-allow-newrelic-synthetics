import boto3
import copy
import requests

URL_NR_SYNTHETICS_IP_RANGE = "https://s3.amazonaws.com/nr-synthetics-assets/nat-ip-dnsname/production/ip.json"
SG_DESCRIPTION = "New Relic Synthetics Monitor"

# Set location labels
NR_LOCATIONS = [
    "Tokyo, JP",
    "San Francisco, CA, USA"
]


def get_nr_synthetics_ip_range(locations: list):
    res = requests.get(URL_NR_SYNTHETICS_IP_RANGE)

    ips_per_location = res.json()

    ips = []
    for location in locations:
        ips.extend(ips_per_location[location])

    ip_ranges = ["{}/32".format(ip) for ip in ips]
    return ip_ranges


def update_sg(security_group_id: str,
              port: int,
              protocol: str,
              cider_ips: list,
              desc: str,
              aws_profile: str = None,
              aws_region: str = "ap-northeast-1",
              ):
    """
    Update security group
    """
    if aws_profile is not None:
        session = boto3.session.Session(profile_name=aws_profile, region_name=aws_region)
        client = session.client("ec2")
    else:
        client = boto3.client("ec2")

    print("Describe current rules.")
    res = client.describe_security_groups(GroupIds=[security_group_id,])
    security_groups = res["SecurityGroups"]

    if len(security_groups) < 1:
        return
    security_group = security_groups[0]

    print(security_group)

    del_ip_permissions = []

    for ip_perm in security_group["IpPermissions"]:
        if ip_perm.get("FromPort") == port and ip_perm.get("ToPort") == port and ip_perm.get("IpProtocol") == "tcp":
            del_ip_ranges = [ip_range for ip_range in ip_perm["IpRanges"] if ip_range.get("Description") == desc]
            del_ip_perm = copy.deepcopy(ip_perm)
            if len(del_ip_ranges) > 0:
                del_ip_perm["IpRanges"] = del_ip_ranges
                del_ip_permissions.append(del_ip_perm)

    if len(del_ip_permissions) > 0:
        print("Delete current rules.")
        print(del_ip_permissions)
        client.revoke_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=del_ip_permissions,
        )
    else:
        print("No deletion targets.")

    print("add rules")
    added_ip_ranges = []
    for cidr_ip in cider_ips:
        ip_range = {
            "CidrIp": cidr_ip,
            "Description": desc
        }
        added_ip_ranges.append(ip_range)

    print(added_ip_ranges)
    client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'FromPort': port,
                'IpProtocol': protocol,
                'IpRanges': added_ip_ranges,
                'ToPort': port,
            },
        ],
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Update security groups to allow New Relic Synthetics Monitor access.")
    parser.add_argument('sg_id', type=str, help="Security Group ID")
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--protocol', type=str, default="tcp")
    parser.add_argument('--description', type=str, default=SG_DESCRIPTION)
    parser.add_argument('--aws-profile', type=str, default=None)
    parser.add_argument('--aws-region', type=str, default=None)

    args = parser.parse_args()

    ips = get_nr_synthetics_ip_range(
        NR_LOCATIONS
    )

    update_sg(args.sg_id,
              args.port,
              args.protocol,
              ips,
              args.description,
              args.aws_profile,
              args.aws_region,
              )
