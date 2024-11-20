# makefile , tab=tab, ts=4
SHELL := /usr/bin/bash

JIRA_SERVER_FILE := ~/.my_jira_server

MY_JIRA_SERVER := $(shell source $(JIRA_SERVER_FILE); echo $${MY_JIRA_SERVER} )
MY_JIRA_PROJECT := $(shell source $(JIRA_SERVER_FILE); echo $${MY_JIRA_PROJECT} )
MY_JIRA_TASK := $(shell source $(JIRA_SERVER_FILE); echo $${MY_JIRA_TASK} )

VENV := ./venv
export VENV
MIN_PYTHON_VERSION := python3.10 # 3.11 3.12
export MIN_PYTHON_VERSION

# PL_LINTERS := eradicate,mccabe,pycodestyle,pyflakes,pylint
PL_LINTERS := eradicate,pycodestyle,pyflakes,pylint

LINE_LENGTH := 120

PACKAGE_NAME := *.py
PY_FILES := *.py

P3_INSTALL := pip3 -q --disable-pip-version-check install

INPUT_SCAN_FILE := ./input/eicarcom2.zip
# INPUT_SCAN_FILE := /usr/bin/vim
# INPUT_SCAN_FILE := ./input/putty-0.80.tar.gz

DEBUG := 0
export DEBUG

OPTIONS_COMMON := \
	--no-verify-cert \
	--jira-issuetype=$(MY_JIRA_TASK) \
	--jira-project=$(MY_JIRA_PROJECT) \
	--jira-server=$(MY_JIRA_SERVER) \
	--issue-template-file='jira_issue_template.json'

OPTIONS := $(OPTIONS_COMMON) \
	--rl-json-report='./report/report.rl.json'
#	--include-violations-pass \
#	--no-split-to-individual-violations
#	--force-new-ticket-on-duplicate

COMMON_VENV := rm -rf $(VENV); \
    $(MIN_PYTHON_VERSION) -m venv $(VENV); \
    source $(VENV)/bin/activate

# during test we do nor remove the report dir
COMMON_TEST := $(MIN_PYTHON_VERSION) -m venv $(VENV); \
    source $(VENV)/bin/activate; \
	$(P3_INSTALL) -r test/requirements.txt; \
	source $(JIRA_SERVER_FILE)

.PHONY: clean prep black pylama mypy all test t2

# ------------------------
# RULES
# ------------------------
all: clean prep test

clean:
	rm -rf $(VENV)
	rm -f *.1 *.2 1 2 *.log
	rm -rf report

# ------------------------
# CODE REVIEW
# ------------------------
prep: black pylama mypy
	mkdir -p ./input
	if [ ! -f ./input/eicarcom2.zip ]; then \
	wget \
		--output-document=./input/eicarcom2.zip \
		https://www.eicar.org/download/eicar-com-2-2/?wpdmdl=8848; \
	fi

black: clean
	$(COMMON_VENV); \
	$(P3_INSTALL) black; \
	black \
		--line-length $(LINE_LENGTH) \
		$(PY_FILES)

pylama: clean
	$(COMMON_VENV); \
	$(P3_INSTALL) setuptools; \
	$(P3_INSTALL) pylama; \
	pylama \
		--max-line-length $(LINE_LENGTH) \
		--linters "${PL_LINTERS}" \
		--ignore "${PL_IGNORE}" \
		$(PY_FILES)

mypy: clean
	$(COMMON_VENV); \
	$(P3_INSTALL) mypy; \
	$(P3_INSTALL) -r test/requirements.txt types-requests; \
	mypy --strict --no-incremental $(PACKAGE_NAME)

# ------------------------
# TESTING
# ------------------------

# test: scan_file debug_test_args
# test: test_to_big_error test_to_big_error4
test: scan_file  make_jira_issue

scan_file:
	rm -rf ./report/
	-./test/scan_file.sh $(INPUT_SCAN_FILE)

debug_test_args:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report='./report/report.rl.json' \
		--attach-file=./test/requirements.txt \
		--attach-file=./makefile \
		--attach-file=./test/scan_file.sh \
			2>$@.2 | tee $@.1
	cat $@.2
	# exit 1

show_task_mandatory_fields:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--show-current-project-task-mandatory-fields \
			2>$@.2 | tee $@.1
	cat $@.2

# create new ticket(s)
make_jira_issue:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS) \
		--attach-file=./report/rl-sdlc.zip \
		--attach-file=./report/report.rl.json \
		2>$@.2 | tee $@.1
	cat $@.2

test_decode_error:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report=$$HOME/Downloads/JuiceShop-13.1.0.rl.json \
			2>$@.2 | tee $@.1
	cat $@.2

test_to_big_error:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report=$$HOME/Downloads/JuiceShop-13.1.0.rl.json \
			2>$@.2 | tee $@.1
	cat $@.2

test_to_big_error2:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report=./input/winclient_installer.rl.json \
			2>$@.2 | tee $@.1
	cat $@.2

test_to_big_error3:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report=./input/winclient_installer.rl.json \
		--no-split-to-individual-violations \
			2>$@.2 | tee $@.1
	cat $@.2

test_to_big_error4:
	$(COMMON_TEST); \
	python3 make_jira_issue.py $(OPTIONS_COMMON) \
		--rl-json-report=./input/winclient_installer.rl.json \
		--no-split-to-individual-violations \
		--include-violations-pass \
			2>$@.2 | tee $@.1
	cat $@.2
