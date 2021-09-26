import argparse
import posixpath
import os
import glob
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
# AFL_PRELOAD=/tmp/fuzzer/libloader.so __TARGET_FUZZEE=libmelsec __TARGET_FUZZEE_PATH=/opt/horizon/lib/horizon/melsec/libmelsec.so __TARGET_SYMBOL=_ZN12_GLOBAL__N_112MelsecParser12processLayerERN7horizon8protocol10management16IProcessingUtilsERNS1_7general11IDataBufferE __FUZZFILE=/tmp/fuzzer/dissectors/libmelsec/fuzzfile.txt afl-fuzz -i /tmp/fuzzer/dissectors/libmelsec/in -o /tmp/fuzzer/dissectors/libmelsec/out/ -f /tmp/fuzzer/dissectors/libmelsec/fuzzfile.txt -m 100000 -M MELSECmaster /opt/horizon/bin/horizon.afl

# _ZN12_GLOBAL__N_112MelsecParser12processLayerERN7horizon8protocol10management16IProcessingUtilsERNS1_7general11IDataBufferE

DEFAULT_FUZZER_DIR = "/tmp/fuzzer/dissectors"
HORIZON_DISSECTORS_DIR = "/opt/horizon/lib/horizon/"
PROCESS_LAYER_SYM = "processLayer"
FUZZ_FILE_NAME = "fuzzfile.txt"
CMD_FILE = "run.cmd"
FUZZER_CMD_TEMPLATE = """AFL_PRELOAD=/tmp/fuzzer/libloader.so __TARGET_FUZZEE={0} __TARGET_FUZZEE_PATH={1} __TARGET_SYMBOL={2} __FUZZFILE={3} afl-fuzz -i {4} -o {5} -f {3} -m 100000 -M {0}master /opt/horizon/bin/horizon.afl"""


def get_func_symbol(path):
    with open(path, 'rb') as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if PROCESS_LAYER_SYM in symbol.name:
                        return symbol.name

    return None


def prepare_dissector(fuzzer_dir, dissector_name):
    dissector_fuzzer_dir = posixpath.join(fuzzer_dir, "lib" + dissector_name)

    if os.path.exists(dissector_fuzzer_dir):
        print("Dissector directory already exist!")
        return False

    dissector_horizon_dir = posixpath.join(HORIZON_DISSECTORS_DIR, dissector_name)

    if not os.path.exists(dissector_horizon_dir):
        print("Dissector {0} was not found in {1}".format(dissector_name, HORIZON_DISSECTORS_DIR))
        return False

    dissector_lib_path = glob.glob("{0}/lib*.so".format(dissector_horizon_dir))[0]
    process_layer_sym = get_func_symbol(dissector_lib_path)

    if not process_layer_sym:
        print("ProcessLayer symbol was not found")
        return False

    print("Dissector lib path: {0}".format(dissector_lib_path))
    print("Found processLayer symbol: {0}".format(process_layer_sym))

    print("Creating dissector directory at: {0}".format(dissector_fuzzer_dir))
    os.mkdir(dissector_fuzzer_dir)

    print("Creating AFL input/output dirs")
    in_dir = posixpath.join(dissector_fuzzer_dir, "in")
    out_dir = posixpath.join(dissector_fuzzer_dir, "out")
    os.mkdir(in_dir)
    os.mkdir(out_dir)

    cmd = FUZZER_CMD_TEMPLATE.format(
        "lib" + dissector_name,
        dissector_lib_path,
        process_layer_sym,
        posixpath.join(dissector_fuzzer_dir, FUZZ_FILE_NAME),
        in_dir,
        out_dir,
    )

    print("Writing cmd: {0}".format(cmd))
    with open(posixpath.join(dissector_fuzzer_dir, CMD_FILE), "w") as fh:
        fh.write(cmd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dissector_name', help='Dissector name')
    parser.add_argument('--fuzzer-dir', default=DEFAULT_FUZZER_DIR, help='Fuzzer Directory')

    args = parser.parse_args()
    prepare_dissector(args.fuzzer_dir, args.dissector_name)


if __name__ == '__main__':
    main()
