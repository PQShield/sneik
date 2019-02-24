# Makefile
# 2019-02-01	Markku-Juhani O. Saarinen <mjos@pqshield.com>

# main file
PROJ		= sneik_spec

# files converted for markdown to latex
MDTEXFILES	= # spec.tex

# All latex source files
TEXFILES	= $(PROJ).tex $(MDTEXFILES)

# Bibfile
BIBFILE		= $(PROJ).bib

# Uses xelatex for additional fonts
$(PROJ).pdf:	$(TEXFILES) $(BIBFILE)
		xelatex $(PROJ)
		bibtex $(PROJ)
		xelatex $(PROJ)
		xelatex $(PROJ)

# Some files are produced from pandoc
%.tex:		%.md
		pandoc -w latex -o $@ $<

# clean does not remove the pdf file result
clean:
		rm -f	*.aux *.dvi *.bbl *.blg *.log *.toc *.lof \
			*.thm *.out \
			$(MDTEXFILES) $(PROJ).pdf $(PROJ)-*.t?z

dist:		clean
		cd ..; \
		tar cfvz $(PROJ)/$(PROJ)-`date "+%Y%m%d%H%M"`.tgz $(PROJ)/*
