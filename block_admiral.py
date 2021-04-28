import json
import argparse
import os
import sys


def is_valid_file(parser, arg):
    """checks that a file path is valid

    Parameters
    ----------
    parser : ArgParse.ArgumentParser
        the argument parser object
    arg : str
        file path to check

    Returns
    -------
    arg : str
        the path to the file if valid
    """
    if not os.path.isfile(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg  # return the arg


def is_positive_integer(parser, arg):
    """checks that an argument is a positive int

    Parameters
    ----------
    parser : ArgParse.ArgumentParser
        the argument parser object
    arg : str
        value to check

    Returns
    -------
    ivalue : int
        integer representation of `arg`
    """
    ivalue = int(arg)
    if ivalue < 0:
        raise parser.ArgumentTypeError("%s is an invalid positive int value" % arg)
    else:
        return ivalue


def parse_args(args):
    parser = argparse.ArgumentParser('Generate Admiral Domain Block List for Untangle WebFilter')

    parser.add_argument("--domains", "-d", dest="domain_file", required=True,
                        type=lambda x: is_valid_file(parser, x),
                        help="the file containing a complete list of Admiral domains to block")

    parser.add_argument("--out_file", "-o", dest="out_file", required=False,
                        default="untangle_admiral_block.json",
                        help="the filename to give the output",
                        type=str)

    parser.add_argument("--start_id", "-s", dest="rule_id", required=False,
                        default=1,
                        help="the first rule ID number to use in the output list",
                        type=lambda x: is_positive_integer(parser, x))

    return parser.parse_args(args)


def write_filter_file(file_path, rules):
    with open(file_path, 'w') as f:
        json.dump(rules, f)


def create_webfilter_rules(domain_name_list, start_id=1):
    filter_rules = []
    for idx, domain in enumerate(domain_name_list, start=start_id):
        filter_rule = {
            "blocked": True,
            "flagged": True,
            "string": domain,
            "javaClass": "com.untangle.uvm.app.GenericRule",
            "name": None,
            "description": "Admiral A**holes",
            "readOnly": None,
            "id": idx,
            "category": None,
            "enabled": None
        }
        filter_rules.append(filter_rule)
    return filter_rules


def read_domain_list(list_path):
    with open(list_path, 'r') as f:
        domains = f.read()
    return domains.split('\n')


if __name__ == '__main__':
    arguments = parse_args(sys.argv[1:])
    domain_list = read_domain_list(list_path=arguments.domain_file)
    webfilter_rules = create_webfilter_rules(domain_name_list=domain_list, start_id=arguments.rule_id)
    write_filter_file(file_path=arguments.out_file, rules=webfilter_rules)
