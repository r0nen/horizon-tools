import posix
import shutil
import subprocess
from datetime import datetime
import os
import glob
import posixpath
import sys
import logging

DISSECTORS_DIR = "/tmp/fuzzer/dissectors"
COVERAGE_DIR_NAME = "coverage"
QUEUE_DIR = "queue"
HORIZON_BINARY_PATH = "/opt/horizon/bin/horizon.afl"
PIN_BINARY_PATH = "/bin/pin"
COVERAGE_SO_PATH = "/tmp/fuzzer/CodeCoverage.so"
COVERAGE_FILE_PATH = "/tmp/fuzzer/trace.log"
LOG_FILE = "/tmp/fuzzer/coverage.log"
FUZZER_DIR = "/tmp/fuzzer"


def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def get_fuzzers():
    fuzzers = []
    for stats in glob.glob(DISSECTORS_DIR+"/**/fuzzer_stats", recursive=True):
        tmp = get_dict(stats)
        if check_pid(int(tmp["fuzzer_pid"])):
            fuzzers.append({"path": stats.replace("fuzzer_stats", ""), "pid": int(tmp["fuzzer_pid"])})
    return fuzzers


def get_dict(ifile):
    info = {}
    data = open(ifile).read().replace(" ", "").split("\n")
    for line in data[:-1]:
        tmp = line.split(":")
        info[tmp[0]] = tmp[1]
    return info


def get_env(pid):
    env_file = open("/proc/{0}/environ".format(pid), "rb").read().decode()
    env_lines = env_file.split("\x00")[:-1]
    env_map = {}
    for line in env_lines:
        values = line.split("=")
        env_map[values[0]] = values[1]

    return env_map


def start_coverage(filter=None):
    logging.info("Starting coverage collection...")
    for fuzzer in get_fuzzers():
        if filter and filter not in fuzzer['path']:
            continue
        pid = fuzzer['pid']
        fuzzer_out_path = fuzzer['path']
        env_map = get_env(pid)

        logging.info("Collecting {0}".format(env_map["__TARGET_FUZZEE"]))
        coverage_dir = posixpath.join(fuzzer_out_path, COVERAGE_DIR_NAME)
        if not os.path.exists(coverage_dir):
            os.mkdir(coverage_dir)

        queue_dir = posixpath.join(fuzzer_out_path, QUEUE_DIR)
        for f in glob.glob("{0}/*".format(queue_dir)):
            f = os.path.basename(f)
            coverage_file = posixpath.join(coverage_dir, f) + ".log"
            if not os.path.exists(coverage_file):
                # LD_PRELOAD=/tmp/fuzzer/libloader.so __TARGET_FUZZEE=libams __TARGET_FUZZEE_PATH=/opt/horizon/lib/horizon/ams/libams.so __TARGET_SYMBOL=_ZN12_GLOBAL__N_19AmsParser12processLayerERN7horizon8protocol10management16IProcessingUtilsERNS1_7general11IDataBufferE __FUZZFILE="$f" pin -t /tmp/fuzzer/CodeCoverage.so -w libams.so -- /opt/horizon/bin/horizon
                # mv ./trace.log ./$(basename "$f").log
                logging.info("Creating coverage: {0}".format(coverage_file))
                os.environ['LD_PRELOAD'] = env_map['AFL_PRELOAD']
                os.environ['__TARGET_FUZZEE'] = env_map['__TARGET_FUZZEE']
                os.environ['__TARGET_FUZZEE_PATH'] = env_map['__TARGET_FUZZEE_PATH']+"clean"
                os.environ['__TARGET_SYMBOL'] = env_map['__TARGET_SYMBOL']
                os.environ['__FUZZFILE'] = posixpath.join(queue_dir, f)
                ret_code = subprocess.run([PIN_BINARY_PATH, "-t", COVERAGE_SO_PATH, "-w",
                                           env_map["__TARGET_FUZZEE"] + ".so"+"clean", "--", HORIZON_BINARY_PATH], stdout=subprocess.DEVNULL)
                if ret_code.returncode:
                    logging.error("Failed to collect coverage: {0}".format(ret_code))
                else:
                    os.rename(COVERAGE_FILE_PATH, coverage_file)


def setup_logger():
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)s]  %(message)s")
    rootLogger = logging.getLogger()

    fileHandler = logging.FileHandler(LOG_FILE)
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)
    rootLogger.setLevel(logging.DEBUG)


def main():
    filter = None
    if len(sys.argv) > 1:
        filter = sys.argv[1]
    os.chdir(FUZZER_DIR)
    setup_logger()
    start_coverage(filter)


if __name__ == "__main__":
    main()