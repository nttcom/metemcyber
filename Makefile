

SOLS_DIR        = contracts
DATA_DIR        = src/metemcyber/core/bc/contracts_data

SOURCE_SOLS     = CTICatalog CTIOperator CTIToken CTIBroker MetemcyberUtil
SOURCE_SOLS     += MetemcyberMinimal AddressGroup
TARGET_ABIS     = $(SOURCE_SOLS:%=$(DATA_DIR)/%.abi.json)
TARGET_COMBINEDS= $(SOURCE_SOLS:%=$(DATA_DIR)/%.combined.json)
VERSIONED_FILES = $(foreach src,$(SOURCE_SOLS),$(src).combined.json-$(shell \
    grep "contractVersion =" $(SOLS_DIR)/$(src).sol |cut -d= -f2 |tr -d ' ;'))

SOLC_ARGS       = @openzeppelin/=$(CURDIR)/node_modules/@openzeppelin/
SOLC_COMMAND    = solc $(SOLC_ARGS) --optimize

all: combined

.PHONY: abi combined
abi: $(TARGET_ABIS)
combined: latest versioned
latest: $(TARGET_COMBINEDS)
versioned: latest
	@cd $(DATA_DIR) && \
	for tgt in $(VERSIONED_FILES); do latest=$${tgt%-*}; [ -L $${latest} ] && continue; \
	    echo "refine linkage: $${latest} -> $${tgt}"; \
	    [ -f $${tgt} -a -f $${latest} ] && (cmp -s $${tgt} $${latest} || \
	        (mv $${tgt} $${tgt}.bak && echo "(backup) $${tgt}.bak")); \
	    mv $${latest} $${tgt} && ln -s $${tgt} $${latest}; done

$(DATA_DIR)/%.abi.json: $(SOLS_DIR)/%.sol
	mkdir -p $(DATA_DIR)
	( cd $(SOLS_DIR) \
	  && ($(SOLC_COMMAND) --abi $*.sol \
	      | grep -A2 "^======= $*.sol:" \
	      | tail -1 \
	     ) \
	) > $@

$(DATA_DIR)/%.combined.json: $(SOLS_DIR)/%.sol
	mkdir -p $(DATA_DIR)
	rm -f $@
	( cd $(SOLS_DIR) \
	  && $(SOLC_COMMAND) --combined-json bin,metadata $*.sol \
	) > $@

.PHONY: clean
clean:
	rm -f $(TARGET_ABIS) $(TARGET_COMBINEDS)
	rm -f $(foreach tgt,$(TARGET_COMBINEDS),$(tgt)-*.bak)

.PHONY: distclean
distclean: clean
	rm -f $(foreach tgt,$(TARGET_COMBINEDS),$(tgt)-*)

.PHONY: abi-earth
abi-earth:
	earth +solc
