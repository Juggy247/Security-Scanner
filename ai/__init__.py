"""AI similarity pipeline.

Import from the submodules (ai.records, ai.text_processing, ai.fetcher, ai.scoring, ai.evaluation). Nothing is
re-exported here on purpose, so importing one part does not pull in the others. Only ai.scoring (and ai.evaluation,
which uses it) loads the embedding library.
"""
