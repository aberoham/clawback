FROM ruby:3.2-bookworm

WORKDIR /site

COPY docs/Gemfile ./
RUN bundle install

COPY docs/ ./
RUN bundle exec jekyll build --trace
