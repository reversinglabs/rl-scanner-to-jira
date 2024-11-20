from typing import (
    Dict,
    List,
    Any,
    Tuple,
)

import logging
import os
import sys
import json
import argparse
from io import StringIO

# import tomllib # works only from python 3.11

from requests import HTTPError
import urllib3

import jira

log = logging.getLogger()

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning,
)

DEBUG = bool(
    int(
        os.getenv(
            "DEBUG",
            0,
        ),
    ),
)

CATEGORY_BASE = "https://docs.secure.software/policies"
CATEGORY_URL_MAP: Dict[str, str] = {
    "vulnerabilities": f"{CATEGORY_BASE}/vulnerabilities",
    "hunting": f"{CATEGORY_BASE}/threat-hunting",
    "hardening": f"{CATEGORY_BASE}/hardening",
    "signatures": f"{CATEGORY_BASE}/digital-signatures",
    "threats": f"{CATEGORY_BASE}/malware-detection",
    "licenses": f"{CATEGORY_BASE}/license-compliance",
    "secrets": f"{CATEGORY_BASE}/sensitive-information",
    "containers": f"{CATEGORY_BASE}/container-security",
    "integrity": f"{CATEGORY_BASE}/package-integrity",
}


def v(msg: str) -> None:
    print(f"verbose {msg}")


def make_logger(logger: logging.Logger) -> None:
    logger.setLevel(logging.DEBUG)

    progName = os.path.basename(sys.argv[0])
    if progName.endswith(".py"):
        progName = progName[:-3]
    fileName = f"{progName}.log"

    fh = logging.FileHandler(fileName)
    fh.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(os.getenv("LOG_LEVEL", "INFO"))

    formatter = logging.Formatter(
        " - ".join(
            [
                "%(asctime)s",
                "%(name)s",
                "%(levelname)s",
                "%(message)s",
            ],
        ),
    )
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)

    # add the handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)


class MyArgs:
    def __init__(
        self,
    ) -> None:
        self.prog = os.path.basename(sys.argv[0])
        self.args: Dict[str, Any] = self._do_args()
        self.get_env_vars()

    @staticmethod
    def _do_args() -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        usage = ""
        epilog = ""
        description = ""

        zz = "mandatory only if not specified via the environment"

        parser = argparse.ArgumentParser(
            description=description,
            usage=usage,
            epilog=epilog,
            prog=os.path.basename(sys.argv[0]),
        )

        parser.add_argument(
            "--verbose",
            "-V",
            action="store_true",
            help="increase verbosity during processing",
        )

        parser.add_argument(
            "--no-verify-cert",
            action="store_true",
            help="do not verify the https cert",
        )
        parser.add_argument(
            "--rl-json-report",
            help="the report to parse: must be in rl-json format",
        )
        parser.add_argument(
            "--attach-file",
            action="append",
            help="upload the specified files for each created issue",
        )
        parser.add_argument(
            "--jira-server",
            "-S",
            help="the jira server url, " + zz,
        )
        parser.add_argument(
            "--jira-token",
            "-T",
            help="the jira access token, " + zz,
        )
        parser.add_argument(
            "--jira-project",
            "-P",
            help="the jira project to create issues in, " + zz,
        )
        parser.add_argument(
            "--jira-issuetype",
            help="the optional jira issue type: default Task",
        )
        parser.add_argument(
            "--no-split-to-individual-violations",
            action="store_true",
            help="the violations section in rhe rl-jsom report will be split into individual tickets",
        )
        parser.add_argument(
            "--include-violations-pass",
            action="store_true",
            help="by default we remove any violation with status 'pass', but you can include them if you wish",
        )
        parser.add_argument(
            "--issue-template-file",
            help="the optional jira issue template file, in json",
        )

        parser.add_argument(
            "--show-current-project-task-mandatory-fields",
            action="store_true",
            help="dont create any new issue, just show the current issues",
        )

        parser.add_argument(
            "--force-new-ticket-on-duplicate",
            action="store_true",
            help="by default we will skip duplicate tickets, but you can enforce a new ticket",
        )

        for k, v in vars(parser.parse_args()).items():
            result[k] = v

        k = "attach_file"
        if k not in result:
            result[k] = []

        if result[k] is None:
            result[k] = []

        rr = []
        for item in result[k]:
            if item not in rr:
                rr.append(item)
        result[k] = rr

        return result

    def get_env_vars(
        self,
    ) -> None:
        # env vars override cli args
        what = {
            "jira_server": "MY_JIRA_SERVER",
            "jira_token": "MY_JIRA_TOKEN",
            "jira_project": "MY_JIRA_PROJECT",
        }
        self.env_names: Dict[str, Any] = {}

        for k, v in what.items():
            z = os.getenv(v, self.args.get(k))
            if z:
                self.args[k] = z

    def validate_mandatory(self) -> None:
        what = [
            "jira_server",
            "jira_token",
            "jira_project",
        ]
        for k in what:
            if self.args.get(k) is None:
                msg = f"mandatory argument {k} was not provided"
                raise Exception(msg)

        if self.args.get("show_current_project_task_mandatory_fields") is False:
            if self.args.get("rl_json_report") is None:
                msg = "rl-json-report is a mandatory requirement"
                raise Exception(msg)

    #     def load_toml_config(
    #         self,
    #     ) -> None:
    #         try:
    #             toml_file = f"{self.prog}.toml"
    #             if not os.path.isfile(toml_file):
    #                 return
    #             with open(toml_file, "rb", encoding="utf8") as f:
    #                 self.toml_data = tomllib.load(f)
    #         except Exception as e:
    #             _ = e

    def get_args(self) -> Dict[str, Any]:
        self.validate_mandatory()
        if self.args.get("verbose"):
            v("my args: " + json.dumps(self.args, indent=2))

        return self.args


class ReportParser:
    def __init__(
        self,
        args: Dict[str, Any],
    ) -> None:
        self.args = args
        self.rl_json_report = self.args.get("rl_json_report")
        self.file_must_be_readable(str(self.rl_json_report))

        with open(str(self.rl_json_report), "r", encoding="utf8") as f:
            self.data = json.load(f)

    @staticmethod
    def file_must_be_readable(
        filename: str,
    ) -> None:
        if not os.path.isfile(filename):
            msg = f"that file does not exist: {filename}"
            log.critical(msg)
            raise Exception(msg)

        if not os.access(filename, os.R_OK):
            msg = f"that file is not readable: {filename}"
            log.critical(msg)
            raise Exception(msg)

    def get_path_dicts(
        self,
        path: str,  # a jq path (no arrays)
    ) -> Any:
        items = path.split(".")[1:]
        r = self.data
        for item in items:
            r = r.get(item)
            if r is None:
                return r
        return r

    def is_global_fail(
        self,
    ) -> bool:
        path = ".report.info.statistics.quality.status"
        item = self.get_path_dicts(path)

        if item is None:
            msg = f"cannot find my path in the data: {path}"
            log.critical(msg)
            raise Exception(msg)

        if item.lower() not in ["pass", "fail"]:
            msg = f"result of path is not valid: {path} -> {item}"
            log.critical(msg)
            raise Exception(msg)

        assert isinstance(item, str)

        return item.lower() == "fail"

    def get_file_name(
        self,
    ) -> str:
        path = ".report.info.file.name"
        item = self.get_path_dicts(path)

        if item is None:
            msg = f"cannot find my path in the data: {path}"
            log.critical(msg)
            raise Exception(msg)

        assert isinstance(item, str)

        return item

    def _extract(self, item: Any) -> Dict[str, Any]:
        rr: Dict[str, Any] = {}
        for k, v in item.items():
            rr[k] = v
        return rr

    def get_violations(
        self,
    ) -> Dict[str, Any]:
        path = ".report.metadata.violations"
        item = self.get_path_dicts(path)

        if item is None:
            msg = f"cannot find my path in the data: {path}"
            log.critical(msg)
            raise Exception(msg)

        return self._extract(item)

    def get_components(
        self,
    ) -> Dict[str, Any]:
        path = ".report.metadata.components"
        item = self.get_path_dicts(path)

        if item is None:
            msg = f"cannot find my path in the data: {path}"
            log.critical(msg)
            raise Exception(msg)

        return self._extract(item)


class JiraMaker:
    def __init__(
        self,
        args: Dict[str, Any],
    ) -> None:
        self.args = args
        self.jira = self.make_jira()

    def upload_file(
        self,
        issue_name: str,
        file_path: str,
    ) -> None:
        issue = self.jira.issue(issue_name)

        if DEBUG:
            print(
                "upload attachment to issue:",
                issue_name,
                file_path,
                file=sys.stderr,
            )

        with open(
            file_path,
            "rb",  # binary mode doesn't take an encoding argument
        ) as f:
            self.jira.add_attachment(
                issue=issue,
                attachment=f,
            )

    def upload_string_as_file(
        self,
        *,
        issue_name: str,
        pseudo_file_name: str,
        data: str,
    ) -> None:
        issue = self.jira.issue(issue_name)

        attachment = StringIO()
        attachment.write(data)

        self.jira.add_attachment(
            issue=issue,
            attachment=attachment,
            filename=pseudo_file_name,
        )

    def make_jira(
        self,
    ) -> jira.JIRA:

        verify_cert = True
        if self.args.get("no_verify_cert") is True:
            verify_cert = False

        return jira.JIRA(
            server=str(self.args.get("jira_server")),
            token_auth=str(self.args.get("jira_token")),
            options={
                "verify": verify_cert,
            },
            logging=True,
        )

    def issue(
        self,
        **kw: Any,
    ) -> jira.Issue:
        try:
            issue = self.jira.issue(
                **kw,
            )
        except HTTPError as e:
            log.exception(f"{e}")
            raise Exception(e)

        return issue

    def make_issue(
        self,
        fields: Dict[str, Any],
    ) -> jira.Issue:
        try:
            new_issue = self.jira.create_issue(
                fields=fields,
            )
        except HTTPError as e:
            log.exception(f"{e}")
            raise Exception(e)

        return new_issue

    def one_new_issue(
        self,
        in_fields: Dict[str, str],
        skip_duplicate_summary: bool = False,
    ) -> jira.Issue | None:
        summary = in_fields.get("summary", "")
        if self.args.get("force_new_ticket_on_duplicate") is False:
            if self.show_current_issues_summary(summary=summary) is not None:
                # a issue with the same summary already exists
                msg = f"duplicate issue already exists with the same summary string: {summary}"
                log.info(msg)
                print(f"INFO: {msg}")
                return None

        fields: Dict[str, Any] = {  # create a minimal structure
            "project": {
                "key": None,
            },
            "summary": "",
            "description": "",
            "issuetype": {
                "name": "Task",
            },
        }
        log.debug(f"fields (base): {fields}")

        # if a file was fiven load the file first,
        # this can handle additional mandatory fields
        merge_file = self.args.get("issue_template_file")
        if merge_file:
            log.info(f"reading template file: {merge_file}")

            with open(merge_file, "r", encoding="utf8") as f:
                data = json.load(f)
                for k, v in data.items():
                    fields[k] = v

            log.debug(f"fields (in template): {fields}")

        # merge the data to a final fields structure for this new issue
        fields["project"]["key"] = self.args.get("jira_project")
        fields["issuetype"]["name"] = self.args.get("jira_issuetype", "Task")

        for k, v in in_fields.items():
            if k in ["upload_components", "upload_violations"]:
                continue

            fields[k] = v

        log.debug(f"fields (after merge): {fields}")  # after merge

        new_issue = self.make_issue(
            fields=fields,
        )

        # upload components via memory upload
        # TODO: upload_components

        for k in ["upload_violations", "upload_components"]:
            if k in in_fields:
                self.upload_string_as_file(
                    issue_name=str(new_issue),
                    pseudo_file_name=f"{k}.json",
                    data=in_fields[k],
                )

        return new_issue

    def search_issues(
        self,
        query: str = "",
    ) -> Any | None:
        if self.args.get("verbose"):
            v(f"search jira: {query}")

        # note archived items will dissapear from search results
        issues = self.jira.search_issues(
            query,
        )

        if self.args.get("verbose"):
            v(f"search jira result: {issues}")

        if len(issues) == 0:
            return None
        return issues

    def show_my_current_issues(
        self,
        who: str | None = None,
    ) -> Any:
        if who is None:
            return self.search_issues()

        query = [
            f"reporter={who}",
        ]

        return self.search_issues(
            " AND ".join(query),
        )

    def show_current_issues_summary(
        self,
        summary: str,
    ) -> Any:
        query = [
            f"summary ~ '{summary}'",
            "project = " + str(self.args.get("jira_project")),
        ]

        rr = self.search_issues(
            " AND ".join(query),
        )

        return rr


class MyApp:
    known_fields = [
        "summary",
        "issuetype",  # we already have this
        "reporter",  # auto
        "project",
    ]
    max_description = 30000

    def __init__(
        self,
        args: Dict[str, Any] = {},
    ) -> None:
        self.args = args
        self.jm = JiraMaker(args=self.args)
        self.verbose = self.args.get("verbose")
        self.tickets: Dict[str, Any] = {}
        self.mandatory_fields_cache: Dict[str, Any] = {}
        self.components: Dict[str, Any] = {}

    def _info(self, msg: str) -> None:
        log.info(msg)
        print(f"INFO: {msg}")

    def _upload_files_to_issue(self, issue_name: str) -> None:
        if self.args.get("attach_file") is None:
            return

        for attach_file_name in self.args.get("attach_file", []):
            self.jm.upload_file(issue_name, attach_file_name)

            msg = f"    attachment: {attach_file_name} uploaded to {issue_name}"
            self._info(msg)

    def _get_components(
        self,
        actual_components: Dict[str, Any],
        my_components: List[str],
    ) -> None:
        for my_component in my_components:
            z = self.components.get(my_component)
            actual_components[my_component] = z

    def _reduce_me(
        self,
        actual_dict: Dict[str, Any],
        what: str,
    ) -> Tuple[bool, str]:
        actual_string = json.dumps(actual_dict, indent=2)
        upload = False
        if len(actual_string) > self.max_description:
            actual_string = f"The {what} are to big, changed to upload: see attachments"
            upload = True
            if DEBUG:
                for key, info in actual_dict.items():
                    print(key, json.dumps(info, indent=2), file=sys.stderr)

        return upload, actual_string

    def _make_single_ticket_from_rl_json_report(
        self,
        status_is_fail: bool,
        viol: Dict[str, Any],
    ) -> Dict[str, Any]:
        what = "Fail" if status_is_fail else "Pass"

        descr = viol.get("description")  # dont call the var description we alread have that
        rule_id = viol.get("rule_id")
        category = viol.get("category")
        priority = viol.get("priority")

        actual_components: Dict[str, Any] = {}
        self._get_components(
            actual_components,
            viol.get(
                "references",
                {},
            ).get(
                "component",
                [],
            ),
        )

        category_url = ""
        if category in CATEGORY_URL_MAP:
            category_url = f": {CATEGORY_URL_MAP[category]}"

        summary = f"RL: {rule_id} - {descr} " + f"File: {self.file_name}"

        upload_components, actual_components_string = self._reduce_me(actual_components, "components")
        upload_violations, actual_violations_string = self._reduce_me(viol, "violations")

        description = f"""
Status: {what}
RL Policy ID: {rule_id}
Description: {descr}
Category: {category}{category_url}
Priority: {priority}
File scanned by RL: {self.file_name}

Violation:
{{code}}{actual_violations_string}{{code}}

Affected components:
{{code}}{actual_components_string}{{code}}
"""

        fields = {
            "summary": summary,
            "description": description,
        }

        if upload_violations is True:
            fields["upload_violations"] = json.dumps(viol, indent=2)

        if upload_components is True:
            fields["upload_components"] = json.dumps(actual_components, indent=2)

        return fields

    def _make_global_ticket_from_rl_json_report(
        self,
        status_is_fail: bool,
        viols: Dict[str, Any],
    ) -> Dict[str, Any]:
        what = "Fail" if status_is_fail else "Pass"
        include_violations_pass = self.args.get("include_violations_pass")

        summary = ", ".join(
            [
                f"RL Status: {what}",
                f"File: {self.file_name}",
            ],
        )

        log.info(f"File name: {self.file_name}")
        log.info(f"Global status: {what}")
        actual_components: Dict[str, Any] = {}  # collect_components

        # sort by category
        rr: Dict[str, Any] = {}
        for kk, vv in viols.items():
            if include_violations_pass is False and vv.get("status").lower() == "pass":
                continue

            self._get_components(
                actual_components,
                vv.get(
                    "references",
                    {},
                ).get(
                    "component",
                    [],
                ),
            )

            category = vv.get("category")
            if category not in rr:
                rr[category] = []
            rr[category].append({kk: vv})

        upload_components, actual_components_string = self._reduce_me(actual_components, "components")
        upload_violations, actual_violations_string = self._reduce_me(rr, "violations")

        description = f"""
Status: {what};
File: {self.file_name}

Volations:
{{code}}{actual_violations_string}{{code}}

Affected components:
{{code}}{actual_components_string}{{code}}
"""

        fields = {
            "summary": summary,
            "description": description,
        }

        if upload_violations is True:
            fields["upload_violations"] = json.dumps(rr, indent=2)

        if upload_components is True:
            fields["upload_components"] = json.dumps(actual_components, indent=2)

        return fields

    def _extract_my_project_my_task(self) -> None:
        self.mandatory_fields_cache = {}
        project = str(self.args.get("jira_project"))
        requested_issue_type = str(self.args.get("jira_issuetype"))
        issue_types = self.jm.jira.project_issue_types(
            project=project,
        )
        for issue_type in issue_types:
            if issue_type.name.lower() != requested_issue_type.lower():
                continue
            self.mandatory_fields_cache[str(issue_type)] = {
                "id": issue_type.id,
                "fields": {},
            }
            issue_fields = self.jm.jira.project_issue_fields(
                project=project,
                issue_type=str(issue_type.id),
            )
            for issue_field in issue_fields:
                if issue_field.required is False or issue_field.hasDefaultValue is True:
                    continue

                self.mandatory_fields_cache[str(issue_type)]["fields"][str(issue_field)] = {}
                z = self.mandatory_fields_cache[str(issue_type)]["fields"][str(issue_field)]

                for a, b in vars(issue_field).items():
                    if a not in ["allowedValues", "name", "fieldId"]:
                        continue
                    if a in ["name", "fieldId"]:
                        z[a] = b
                        continue
                    z[a] = {}
                    for element in b:
                        z[a][str(element)] = element

    def show_current_project_task_mandatory_fields(self) -> None:
        self._extract_my_project_my_task()
        n = "fieldId"
        for a in self.mandatory_fields_cache:
            print(f"{a}:")
            for b in self.mandatory_fields_cache[a]["fields"]:
                known = False
                if self.mandatory_fields_cache[a]["fields"][b].get(n) in self.known_fields:
                    known = True

                print(f"  {b}: {'Known' if known else 'Unknown: This field must be added to the json template'}")

                for c in self.mandatory_fields_cache[a]["fields"][b]:
                    if c not in ["allowedValues"]:
                        print(f"    {c}:", self.mandatory_fields_cache[a]["fields"][b][c])
                        continue

                    print(f"    {c}:")
                    for val in self.mandatory_fields_cache[a]["fields"][b][c]:
                        print("      ", val)

    def extract_ticket_info(
        self,
    ) -> None:
        include_violations_pass = self.args.get("include_violations_pass")
        if include_violations_pass is False and self.status_is_fail is False:
            msg = (
                f"File: {self.file_name}; "
                + "No issue created: scan produced status: 'Pass' and 'include_violations_pass' is False"
            )
            self._info(msg)
            return

        viols = self.rp.get_violations()
        self.components = self.rp.get_components()

        no_split_to_individual_violations = self.args.get("no_split_to_individual_violations")
        if no_split_to_individual_violations is True:
            fields = self._make_global_ticket_from_rl_json_report(
                status_is_fail=self.status_is_fail,
                viols=viols,
            )
            self.tickets[str(fields.get("summary"))] = fields
            return

        for key, viol in viols.items():
            status = viol.get("status")

            if status.lower() == "pass" and include_violations_pass is False:
                msg = f"skip: category: {viol.get('category')}, rule: {viol.get('rule_id')}, status: {status}"
                self._info(msg)
                continue

            fields = self._make_single_ticket_from_rl_json_report(
                status_is_fail=status.lower() == "fail",
                viol=viol,
            )
            if fields is not None:
                title = ", ".join(
                    [
                        f"category: {viol.get('category')}",
                        f"rule: {viol.get('rule_id')}",
                        f"status: {viol.get('status')}",
                    ]
                )

                self.tickets[title] = fields

    def load_report(self) -> None:
        self.rp = ReportParser(args=self.args)
        self.file_name = self.rp.get_file_name()
        self.status_is_fail = self.rp.is_global_fail()
        self.what = "Fail" if self.status_is_fail else "Pass"

    def make_jira_tickets(
        self,
    ) -> None:

        if len(self.tickets) == 0:
            msg = f"no tickets created: file: {self.file_name}, report_status: {self.what}"
            self._info(msg)
            return

        for title, fields in self.tickets.items():
            if DEBUG:
                print(title, fields, file=sys.stderr)

            new_issue = self.jm.one_new_issue(in_fields=fields)
            if not new_issue:
                continue

            msg = f"new ticket create: {new_issue}: {title}"
            self._info(msg)

            self._upload_files_to_issue(str(new_issue))


def main() -> None:
    make_logger(log)
    ma = MyArgs()
    args = ma.get_args()

    if DEBUG:
        print(json.dumps(args, indent=2), file=sys.stderr)

    app = MyApp(args=args)

    if args.get("show_current_project_task_mandatory_fields"):
        app.show_current_project_task_mandatory_fields()
        sys.exit(0)

    app.load_report()
    app.extract_ticket_info()
    app.make_jira_tickets()


main()
