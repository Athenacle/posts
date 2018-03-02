---
title: LanguageTest
date: 2018-03-02 
tag: lang,test,
---

# C
## clike test
```c{1,2}
    /* Hello World in C, Ansi-style */

    #include <stdio.h>
    #include <stdlib.h>
    #include <X11/Intrinsic.h>
    #include <X11/StringDefs.h>
    #include <X11/Xaw/Label.h>

    main(int argc,char **argv)
    {
        XtAppContext app_context;
        Widget toplevel,hello;

        toplevel = XtVaAppInitialize(&app_context,"XHello",NULL,0,
                                     &argc,argv,NULL,NULL);
        hello = XtVaCreateManagedWidget("Hello World!",labelWidgetClass,
                                        toplevel,(void*)0);

        XtRealizeWidget(toplevel);

        XtAppMainLoop(app_context);
        return 0;
    }

```

# C++
### cpptest
```cpp
    #include "driver/wxcc.h"
    #include "lex/lex_parser.h"
    #include "lex/lex_types.h"

    #include "lex/macro.h"
    #include "driver/diagnostic.h"
    #include "driver/file.h"
    #include "driver/printer.h"
    #include "driver/runtime_config.h"
    #include "driver/timer.h"

    using core::TimeStatistic;
    using core::driver::PrintMessage;
    using core::driver::PrintTimeStatistic;
    using core::driver::PrintVerbose;
    using core::driver::RuntimeConfig;
    using lexer::MacroProcessor;
    using tool::File;


    int main(int argc, char* argv[])
    {
        TimeStatistic ts(STRING("Command Line Options Parsing"));
        ts.begin();
        RuntimeConfig& config = RuntimeConfig::GetRuntimeConfig();
        config.ParseCommandArgs(argc, argv);
        ts.end();
        PrintTimeStatistic(ts);

        auto files = config.getInputFiles();
        for (auto& file : files) {
            File reader(file);
            StringBuilder PreProcessed;
            //  MacroProcessor mp(config.getIncludeDirectories(), PreProcessed, reader);
            //mp.BeginPreProcess();
            //std::COUT << PreProcessed.c_str();
            reader.ReadFile(PreProcessed);

            lexer::LexParser lp(PreProcessed, file.c_str());
            lexer::Token* to;
            do {
                to = lp.next();
                if (to != nullptr) {
                    PrintVerbose(STRING("$"), to->print());
                    delete to;
                }

            } while (to != nullptr);

            config.Destroy();
            return 0;
        }
    }
```

# Python
```python
    #!/usr/bin/env python2

    from __future__ import print_function
    from __future__ import with_statement

    import sys
    import collections

    # Generate kernel config diff.

    """Check config changed in two linux kernel config files"""


    def read_config_into_dict(config_file):
        return_dict = collections.OrderedDict()
        with open(config_file, 'r') as filep:
            for line in filep:
                line = line.strip()
                if line == '':
                    continue
                else:
                    if line.startswith('#'):  # this line is a config comment.
                        continue
                    splited = line.split("=")
                    return_dict[splited[0]] = splited[1]
            return return_dict


    def append_new_set_remove(the_dict, string_list, string_format):
        items = the_dict.items()
        for c_key, c_value in items:
            string = string_format % (c_key, c_value)
            string_list.append(string)


    def check_config_diff(new_dict, old_dict):
        new_dict, old_dict = strip_same_lines(new_dict, old_dict)
        old_items = old_dict.items()
        r_list = list()
        for c_key, c_value in old_items:
            if c_key not in new_dict:
                continue
            string = "* %-50s: %-5s -> %-5s\n" % (c_key, c_value, new_dict[c_key])
            r_list.append(string)
            new_dict.pop(c_key)
            old_dict.pop(c_key)
        if len(new_dict) > 0:
            append_new_set_remove(new_dict, r_list, "+ %-50s: Unset -> %-5s\n")
        if len(old_dict) > 0:
            append_new_set_remove(old_dict, r_list, "- %-50s: %-5s -> Unset\n")
        return r_list


    def strip_same_lines(new_dict, old_dict):
        old_items = old_dict.items()
        for c_key, c_value in old_items:
            if c_key in new_dict and new_dict[c_key] == c_value:
                new_dict.pop(c_key)
                old_dict.pop(c_key)
        return new_dict, old_dict


    def write_diff_to_file(diff_lines, result_file, detail_string):
        with open(result_file, 'a') as dest_f:
            dest_f.write(detail_string)
            dest_f.write("Total Changed " + str(len(diff_lines)) + ".\n")
            dest_f.write("=============BEGIN========================\n")
            dest_f.writelines(diff_lines)
            dest_f.write("=============END==========================\n")


    def main(old_config, new_config, result_file):
        new_config_list = read_config_into_dict(new_config)
        old_config_list = read_config_into_dict(old_config)
        diff = check_config_diff(new_config_list, old_config_list)
        detail_string = """Config Change from %s -> %s\n\n* : Changed\n- : Removed
    + : Added.\n""" % (old_config, new_config)
        write_diff_to_file(diff, result_file, detail_string)


    if __name__ == '__main__':
        usage = "./kernel_config_diff.py <old_config> <new_config> <result_file>"
        if len(sys.argv) != 4:
            print(usage)
        else:
            main(sys.argv[1], sys.argv[2], sys.argv[3])
```


# Java
```java
    /*
     * Copyright (c) 2017 WangXiao zjjhwxc(at)gmail.com
     *
     * This source file belongs to my MISCellaneous project.  
     * Which contains different kinds of short source code.
     * This project was released under MIT License. Please Read LICENSE file in root directory.
     *
     */

    /*
     * This file used for generate jump table for input keywords.
     * Please NOTE: this jump table is huge in size.
     * And because of cache miss, its performance may be bad.
     *
     *
     *  while (*str && *str != ' ' && state != 0xff) {
     *           state = tables[state][*str - 'a'];
     *           str++;
     *  }
     *
     */

    package xyz.athenacle.misc.compiler.utils;

    public class FSMStateGenerator {
        private static final String keywords = "auto break case char const continue default do double else enum extern " +
            "float for goto if inline int long register restrict return short signed sizeof static struct switch " +
            "typedef union unsigned void volatile while";

        private static final int error_state = 0xff; //TODO change this is necessary


        private int table[][];

        private int begin_state = 0;
        private final int row = 26;
        private final int states = 400; //TODO change this if necessary.

        private int now_state = 2;

        private String comments[];

        void build_table() {
            table = new int[states][row];
            comments = new String[states];
            for (int i = 0; i < states; i++) {
                for (int j = 0; j < row; j++) {
                    table[i][j] = error_state;
                }
            }
        }

        void add_to_table(String k) {
            begin_state = 1;
            int next_line = begin_state;
            char chars[] = k.toCharArray();
            String comment = "";
            for (char c : chars) {
                int next_row = c - 'a';
                int state = table[next_line][next_row];
                comment = comment + Character.toString(c);
                if (state == 0xff) {
                    next_line = table[next_line][next_row] = now_state;
                    comments[now_state] = comment;
                    now_state++;

                } else {
                    next_line = table[next_line][next_row];
                }
            }
            System.out.println("ACCEPT(" + k.toUpperCase() + ", " + hex_print(now_state - 1) + "),");
            //TODO change this if  necessary
        }

        void build() {
            build_table();
            String keyword[] = keywords.split(" ");
            for (String k : keyword) {
                add_to_table(k);
            }

            for (int i = 0; i < now_state; i++) {
                for (int j = 0; j < row; j++) {
                    if (table[i][j] == 0xff) {
                        table[i][j] = 0;
                    }
                }

            }
            now_state++;
        }

        String hex_print(int h) {

    //        String hex = Integer.toHexString(h);
    //        if (hex.length() == 1) {
    //            hex = "0" + hex;
    //        }
    //        return "0x" + hex;
            return Integer.toString(h);
        }

        void print() {
            StringBuilder builder = new StringBuilder();
            builder.append("/*");
            for (int i = 0; i < 26; i++) {
                builder.append("  ").append(Character.toString((char) (i + 'a'))).append("  ");
            }
            builder.append(" */");
            for (int i = 0; i < now_state - 1; i++) {
                builder.append("\n{ ");
                String state = hex_print(i);

                for (int j = 0; j < row; j++) {
                    builder.append(hex_print(table[i][j]));
                    if (j < (row - 1))
                        builder.append(',');
                }
                builder.append("},\t");//.append("\t\t /* ").append(state).append(" ").append(comments[i]).append("  */");
            }
            System.out.println(builder.toString());
        }

        public static void main(String[] args) {
            FSMStateGenerator main = new FSMStateGenerator();
            main.build();
            main.print();
        }
    }
```

# Bash
```bash
    #!/bin/sh


    dest_dev="/dev/sdc";


    status(){
        sudo parted --script "$dest_dev" print
    }

    init(){

        parted_script="$(mktemp)"
        dd if=/dev/zero of="$dest_dev" seek=1 count=4096
        cat >> "$parted_script" << EOF
    unit MB

    mklabel gpt

    mkpart primary fat32 1 98%
    toggle 1 esp
    name 1 EFI

    mkpart primary ext4 98% 100%
    toggle 2 bios_grub
    name 2 BIOS

    quit

    EOF
        parted "$dest_dev" < "$parted_script"

        mkfs.vfat -F 32 "$dest_dev"1
        mkfs.ext4 -F "$dest_dev"2

        mnt_dir="$(mktemp -d)"
        mount "$dest_dev"1 "$mnt_dir"
        mkdir -p "$mnt_dir/boot"
        grub-install --target=i386-pc --recheck --boot-directory="$mnt_dir/boot" "$dest_dev"
        grub-install --target x86_64-efi --efi-directory "$mnt_dir" --boot-directory="$mnt_dir/boot" --removable
        umount "$mnt_dir"
    }

    init
    status

    update(){
        mnt_dir="$(mktemp -d)"
        mount "$dest_dev"1 "$mnt_dir"

        cat >> "$mnt_dir"/boot/grub/grub.cfg << EOF
        set default=0
        set fallback=1
        set gfxmode=1024x768,auto
        set locale_dir=$prefix/locale
        set pager=1
        set timeout=500

        insmod part_gpt
        insmod part_msdos
        insmod ext2
        insmod fat
        insmod iso9660
        insmod ntfs
        insmod udf
        insmod all_video
        insmod gfxterm

    EOF
    }
```

# Javascript
```javascript
    /*
     * https://athenacle.xyz site source file.
     *
     * Powered by Gastby
     *
     * Copyright (c) 2018 Athenacle (zjjhwxc@gmail.com)
     *
     * This file is released under MIT license. Please refer to LICENSE file for more details.
     *
     */

    /*
     * gatsby-node/createPages.js
     *
     * gatsby-node API: createPages
     */

    const path = require('path');
    const slash = require('slash');
    const {
        output,
        buildPostPath,
        buildTagPath,
        realtivePath,
        md5AsKey
    } = require('../src/utils/utils');


    const allOrgaGraphql = `
                {
                    allOrga {
                        edges {
                            node {
                                fileAbsolutePath
                                path
                                category
                                tags
                                title
                                time
                                fields{
                                    slug
                                }
                            }
                        }
                    }
                }
            `;

    module.exports = ({ graphql, boundActionCreators }) => {
        const { createPage } = boundActionCreators;

        return new Promise((resolve, reject) => {
            const orgPostTemplate = path.resolve('src/templates/post_org.jsx');
            const tagTemplate = path.resolve('src/templates/tag.jsx');
            const tagCloudTemplate = path.resolve('src/templates/tag_cloud.jsx');
            graphql(allOrgaGraphql).then(result => {
                if (result.errors) {
                    reject(result.errors);
                } else {
                    let orgaEdges = result.data.allOrga.edges;
                    let tagList = {};
                    let pages = [];
                    let categoryList = {};
                    orgaEdges.forEach(edge => {
                        let tags = edge.node.tags;
                        let category = edge.node.category;
                        let title = edge.node.title;
                        if (category != undefined) {
                            if (!categoryList.hasOwnProperty(category)) {
                                categoryList[category] = {
                                    name: category,
                                    pages: []
                                };
                            }
                            categoryList[category].pages.push(path);
                            edge.node.category = category;
                        }
                        if (tags != undefined) {
                            tags.forEach(t => {
                                if (!(t in tagList)) {
                                    tagList[t] = { count: 0, key: md5AsKey(t) };
                                }
                                tagList[t].count++;
                            });
                        }
                        if (title === undefined) {
                            output.error(
                                `ORG File with slug ${realtivePath(
                                    edge.node.fileAbsolutePath
                                )} does not have a title. Refuse to createPage`
                            );
                        } else {
                            pages.push({
                                node: edge.node,
                                path: buildPostPath(edge.node.path),
                                component: slash(orgPostTemplate),
                                context: { path: edge.node.path, tag: tagList }
                            });
                        }
                    });
                    pages.sort((a, b) => {
                        let at = a.node.time;
                        let bt = b.node.time;
                        return at.valueOf() - bt.valueOf();
                    });
                    pages.forEach(page => {
                        createPage(page);
                    });

                    for (var t in tagList) {
                        createPage({
                            path: buildTagPath(t),
                            component: slash(tagTemplate),
                            context: { tag: t }
                        });
                    }
                    createPage({
                        path: '/tags/index.html',
                        component: slash(tagCloudTemplate),
                        context: { tag: tagList }
                    });
                }
                resolve();
            });
        });
    };
```

# Ruby
```ruby   

    require "base64"

    require "http/headers"

    module HTTP
      module Chainable
        # Request a get sans response body
        # @param uri
        # @option options [Hash]
        def head(uri, options = {}) # rubocop:disable Style/OptionHash
          request :head, uri, options
        end

        # Get a resource
        # @param uri
        # @option options [Hash]
        def get(uri, options = {}) # rubocop:disable Style/OptionHash
          request :get, uri, options
        end

        # Post to a resource
        # @param uri
        # @option options [Hash]
        def post(uri, options = {}) # rubocop:disable Style/OptionHash
          request :post, uri, options
        end

        # Put to a resource
        # @param uri
        # @option options [Hash]
        def put(uri, options = {}) # rubocop:disable Style/OptionHash
          request :put, uri, options
        end

        # Delete a resource
        # @param uri
        # @option options [Hash]
        def delete(uri, options = {}) # rubocop:disable Style/OptionHash
          request :delete, uri, options
        end

        # Echo the request back to the client
        # @param uri
        # @option options [Hash]
        def trace(uri, options = {}) # rubocop:disable Style/OptionHash
          request :trace, uri, options
        end

        # Return the methods supported on the given URI
        # @param uri
        # @option options [Hash]
        def options(uri, options = {}) # rubocop:disable Style/OptionHash
          request :options, uri, options
        end

        # Convert to a transparent TCP/IP tunnel
        # @param uri
        # @option options [Hash]
        def connect(uri, options = {}) # rubocop:disable Style/OptionHash
          request :connect, uri, options
        end

        # Apply partial modifications to a resource
        # @param uri
        # @option options [Hash]
        def patch(uri, options = {}) # rubocop:disable Style/OptionHash
          request :patch, uri, options
        end

        # Make an HTTP request with the given verb
        # @param verb
        # @param uri
        # @option options [Hash]
        def request(verb, uri, options = {}) # rubocop:disable Style/OptionHash
          branch(options).request verb, uri
        end

        # Prepare an HTTP request with the given verb
        # @param verb
        # @param uri
        # @option options [Hash]
        def build_request(verb, uri, options = {}) # rubocop:disable Style/OptionHash
          branch(options).build_request verb, uri
        end

        # @overload timeout(options = {})
        #   Adds per operation timeouts to the request
        #   @param [Hash] options
        #   @option options [Float] :read Read timeout
        #   @option options [Float] :write Write timeout
        #   @option options [Float] :connect Connect timeout
        # @overload timeout(global_timeout)
        #   Adds a global timeout to the full request
        #   @param [Numeric] global_timeout
        def timeout(options)
          klass, options = case options
                           when Numeric then [HTTP::Timeout::Global, {:global => options}]
                           when Hash    then [HTTP::Timeout::PerOperation, options]
                           when :null   then [HTTP::Timeout::Null, {}]
                           else raise ArgumentError, "Use `.timeout(global_timeout_in_seconds)` or `.timeout(connect: x, write: y, read: z)`."

                           end

          %i[global read write connect].each do |k|
            next unless options.key? k
            options["#{k}_timeout".to_sym] = options.delete k
          end

          branch default_options.merge(
                   :timeout_class => klass,
                   :timeout_options => options
                 )
        end

        # @overload persistent(host, timeout: 5)
        #   Flags as persistent
        #   @param  [String] host
        #   @option [Integer] timeout Keep alive timeout
        #   @raise  [Request::Error] if Host is invalid
        #   @return [HTTP::Client] Persistent client
        # @overload persistent(host, timeout: 5, &block)
        #   Executes given block with persistent client and automatically closes
        #   connection at the end of execution.
        #
        #   @example
        #
        #       def keys(users)
        #         HTTP.persistent("https://github.com") do |http|
        #           users.map { |u| http.get("/#{u}.keys").to_s }
        #         end
        #       end
        #
        #       # same as
        #
        #       def keys(users)
        #         http = HTTP.persistent "https://github.com"
        #         users.map { |u| http.get("/#{u}.keys").to_s }
        #       ensure
        #         http.close if http
        #       end
        #
        #
        #   @yieldparam [HTTP::Client] client Persistent client
        #   @return [Object] result of last expression in the block
        def persistent(host, timeout: 5)
          options  = {:keep_alive_timeout => timeout}
          p_client = branch default_options.merge(options).with_persistent host
          return p_client unless block_given?
          yield p_client
        ensure
          p_client.close if p_client
        end

        # Make a request through an HTTP proxy
        # @param [Array] proxy
        # @raise [Request::Error] if HTTP proxy is invalid
        def via(*proxy)
          proxy_hash = {}
          proxy_hash[:proxy_address]  = proxy[0] if proxy[0].is_a?(String)
          proxy_hash[:proxy_port]     = proxy[1] if proxy[1].is_a?(Integer)
          proxy_hash[:proxy_username] = proxy[2] if proxy[2].is_a?(String)
          proxy_hash[:proxy_password] = proxy[3] if proxy[3].is_a?(String)
          proxy_hash[:proxy_headers]  = proxy[2] if proxy[2].is_a?(Hash)
          proxy_hash[:proxy_headers]  = proxy[4] if proxy[4].is_a?(Hash)

          raise(RequestError, "invalid HTTP proxy: #{proxy_hash}") unless (2..5).cover?(proxy_hash.keys.size)

          branch default_options.with_proxy(proxy_hash)
        end
        alias through via

        # Make client follow redirects.
        # @param opts
        # @return [HTTP::Client]
        # @see Redirector#initialize
        def follow(options = {}) # rubocop:disable Style/OptionHash
          branch default_options.with_follow options
        end

        # Make a request with the given headers
        # @param headers
        def headers(headers)
          branch default_options.with_headers(headers)
        end

        # Make a request with the given cookies
        def cookies(cookies)
          branch default_options.with_cookies(cookies)
        end

        # Force a specific encoding for response body
        def encoding(encoding)
          branch default_options.with_encoding(encoding)
        end

        # Accept the given MIME type(s)
        # @param type
        def accept(type)
          headers Headers::ACCEPT => MimeType.normalize(type)
        end

        # Make a request with the given Authorization header
        # @param [#to_s] value Authorization header value
        def auth(value)
          headers Headers::AUTHORIZATION => value.to_s
        end

        # Make a request with the given Basic authorization header
        # @see http://tools.ietf.org/html/rfc2617
        # @param [#fetch] opts
        # @option opts [#to_s] :user
        # @option opts [#to_s] :pass
        def basic_auth(opts)
          user = opts.fetch :user
          pass = opts.fetch :pass

          auth("Basic " + Base64.strict_encode64("#{user}:#{pass}"))
        end

        # Get options for HTTP
        # @return [HTTP::Options]
        def default_options
          @default_options ||= HTTP::Options.new
        end

        # Set options for HTTP
        # @param opts
        # @return [HTTP::Options]
        def default_options=(opts)
          @default_options = HTTP::Options.new(opts)
        end

        # Set TCP_NODELAY on the socket
        def nodelay
          branch default_options.with_nodelay(true)
        end

        # Turn on given features. Available features are:
        # * auto_inflate
        # * auto_deflate
        # @param features
        def use(*features)
          branch default_options.with_features(features)
        end

        private

        # :nodoc:
        def branch(options)
          HTTP::Client.new(options)
        end
      end
    end
```

# Elisp
```emacs
    ;;; Code:

    (require 'seq)

    ;;; get .emacs.d abslute path and output file from argv

    (when (not (= (length argv) 2))
      (message "%s\n%s" "Argument error."
               "Usage: emacs -Q --script generate-rsync-list.el <path to .emacs.d> <dest file>")
      (kill-emacs 255))

    (defvar athenacle|emacs-d-path (elt argv 0))
    (defvar athenacle|dest-file-path (elt argv 1))

    (defconst spacemacs-layer-directory (expand-file-name (concat athenacle|emacs-d-path "/layers")))

    (unless (file-directory-p spacemacs-layer-directory)
      (message "PATH %s dot exist." spacemacs-layer-directory)
      (kill-emacs 255))

    (message ".emacs.d true path: %s" athenacle|emacs-d-path) ;; .emacs.d true path
    (message "layer directroy list file path: %s" athenacle|dest-file-path) ;; output dest file path

    ;;; get layer list from spacemacs configuration file.

    (defvar dotspacemacs-configuration-layers)
    (defconst dotspacemacs-configuration-file-home (expand-file-name "~/.spacemacs"))
    (defconst dotspacemacs-configuration-file-dotspacmacs (expand-file-name "~/.spacemacs.d/init.el"))

    (defconst dotspacemacs-configuration-file
      (if (file-exists-p dotspacemacs-configuration-file-home)
          dotspacemacs-configuration-file-home
        dotspacemacs-configuration-file-dotspacmacs))

    (load-file dotspacemacs-configuration-file)
    (dotspacemacs/layers)

    (dolist (a '(ivy groovy treemacs
                     spacemacs-bootstrap spacemacs spacemacs-base
                     spacemacs-docker spacemacs-editing spacemacs-editing
                     spacemacs-visual spacemacs-navigation spacemacs-org
                     spacemacs-editing-visual spacemacs-evil spacemacs-layouts
                     spacemacs-language spacemacs-purpose spacemacs-modeline
                     spacemacs-misc spacemacs-completion neotree))
      (push a dotspacemacs-configuration-layers))
    (defvar dotspacemacs-layers (seq-map (lambda(n) (if (listp n) (car n) n)) dotspacemacs-configuration-layers))

    ;;; get all layer categories from spacemacs

    (defvar spacemacs-layer-cates
      (seq-filter
       (lambda (f)
         (and  (string-prefix-p "+" f)
               (file-directory-p (expand-file-name (concat spacemacs-layer-directory "/" f)))))
       (directory-files spacemacs-layer-directory)))

    ;;; find out each layer belongs to which category, build a list, result may like
    ;; (("+web-services"
    ;;   ("elfeed"))
    ;;  ("+tools"
    ;;   ("shell"))
    ;;  ("+tags"
    ;;   ("gtags"))
    ;;  ("+source-control"
    ;;   ("git"))
    ;;  ("+lang"
    ;;   ("shell-scripts" "scheme" "python" "lua" "javascript" "java" "go" "emacs-lisp" "c-c++"))
    ;;  ("+intl"
    ;;   ("chinese"))
    ;;  ("+fun"
    ;;   ("emoji"))
    ;;  ("+emacs"
    ;;   ("org"))
    ;;  ("+completion"
    ;;   ("helm" "auto-completion"))
    ;;  ("+checkers"
    ;;   ("syntax-checking" "spell-checking"))
    ;;  ("+chat"
    ;;   ("rcirc")))

    (defvar athenacle|enabled-layers-cates '())

    (dolist (cate spacemacs-layer-cates)
      (let ((layers-list '()))
        (let ((layers (directory-files (concat spacemacs-layer-directory "/" cate))))
          (dolist (layer layers)
            (when (member (intern layer) dotspacemacs-layers)
              (add-to-list 'layers-list layer))))
        (when (not (eq 0 (length layers-list)))
          (add-to-list 'athenacle|enabled-layers-cates (cons cate (list layers-list))))))

    ;;; generate file list output
    (defvar athenacle|layers-list-output "")

    (seq-do
     (lambda (n)
       (let ((cate (car n)))
         (seq-do (lambda (l) (setq athenacle|layers-list-output (concat athenacle|layers-list-output (format "layers/%s/%s\n" cate l)))) (car(cdr n)))))
     athenacle|enabled-layers-cates)

    ;;; write file to dest
    (write-region athenacle|layers-list-output nil athenacle|dest-file-path 'append)

    (provide 'generate-rsync-list)
    ;;; generate-rsync-list.el ends here
```

* Go
``` go
    package aws

    import (
        "log"
        "os"
    )

    // A LogLevelType defines the level logging should be performed at. Used to instruct
    // the SDK which statements should be logged.
    type LogLevelType uint

    // LogLevel returns the pointer to a LogLevel. Should be used to workaround
    // not being able to take the address of a non-composite literal.
    func LogLevel(l LogLevelType) *LogLevelType {
        return &l
    }

    // Value returns the LogLevel value or the default value LogOff if the LogLevel
    // is nil. Safe to use on nil value LogLevelTypes.
    func (l *LogLevelType) Value() LogLevelType {
        if l != nil {
            return *l
        }
        return LogOff
    }

    // Matches returns true if the v LogLevel is enabled by this LogLevel. Should be
    // used with logging sub levels. Is safe to use on nil value LogLevelTypes. If
    // LogLevel is nil, will default to LogOff comparison.
    func (l *LogLevelType) Matches(v LogLevelType) bool {
        c := l.Value()
        return c&v == v
    }

    // AtLeast returns true if this LogLevel is at least high enough to satisfies v.
    // Is safe to use on nil value LogLevelTypes. If LogLevel is nil, will default
    // to LogOff comparison.
    func (l *LogLevelType) AtLeast(v LogLevelType) bool {
        c := l.Value()
        return c >= v
    }

    const (
        // LogOff states that no logging should be performed by the SDK. This is the
        // default state of the SDK, and should be use to disable all logging.
        LogOff LogLevelType = iota * 0x1000

        // LogDebug state that debug output should be logged by the SDK. This should
        // be used to inspect request made and responses received.
        LogDebug
    )

    // Debug Logging Sub Levels
    const (
        // LogDebugWithSigning states that the SDK should log request signing and
        // presigning events. This should be used to log the signing details of
        // requests for debugging. Will also enable LogDebug.
        LogDebugWithSigning LogLevelType = LogDebug | (1 << iota)

        // LogDebugWithHTTPBody states the SDK should log HTTP request and response
        // HTTP bodys in addition to the headers and path. This should be used to
        // see the body content of requests and responses made while using the SDK
        // Will also enable LogDebug.
        LogDebugWithHTTPBody

        // LogDebugWithRequestRetries states the SDK should log when service requests will
        // be retried. This should be used to log when you want to log when service
        // requests are being retried. Will also enable LogDebug.
        LogDebugWithRequestRetries

        // LogDebugWithRequestErrors states the SDK should log when service requests fail
        // to build, send, validate, or unmarshal.
        LogDebugWithRequestErrors
    )

    // A Logger is a minimalistic interface for the SDK to log messages to. Should
    // be used to provide custom logging writers for the SDK to use.
    type Logger interface {
        Log(...interface{})
    }

    // A LoggerFunc is a convenience type to convert a function taking a variadic
    // list of arguments and wrap it so the Logger interface can be used.
    //
    // Example:
    //     s3.New(sess, &aws.Config{Logger: aws.LoggerFunc(func(args ...interface{}) {
    //         fmt.Fprintln(os.Stdout, args...)
    //     })})
    type LoggerFunc func(...interface{})

    // Log calls the wrapped function with the arguments provided
    func (f LoggerFunc) Log(args ...interface{}) {
        f(args...)
    }

    // NewDefaultLogger returns a Logger which will write log messages to stdout, and
    // use same formatting runes as the stdlib log.Logger
    func NewDefaultLogger() Logger {
        return &defaultLogger{
            logger: log.New(os.Stdout, "", log.LstdFlags),
        }
    }

    // A defaultLogger provides a minimalistic logger satisfying the Logger interface.
    type defaultLogger struct {
        logger *log.Logger
    }

    // Log logs the parameters to the stdlib logger. See log.Println.
    func (l defaultLogger) Log(args ...interface{}) {
        l.logger.Println(args...)
    }
```

# Rust
``` rust
// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The arena, a fast but limited type of allocator.
//!
//! Arenas are a type of allocator that destroy the objects within, all at
//! once, once the arena itself is destroyed. They do not support deallocation
//! of individual objects while the arena itself is still alive. The benefit
//! of an arena is very fast allocation; just a pointer bump.
//!
//! This crate implements `TypedArena`, a simple arena that can only hold
//! objects of a single type.

#![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
       html_favicon_url = "https://doc.rust-lang.org/favicon.ico",
       html_root_url = "https://doc.rust-lang.org/nightly/",
       test(no_crate_inject, attr(deny(warnings))))]
#![deny(warnings)]

#![feature(alloc)]
#![feature(core_intrinsics)]
#![feature(dropck_eyepatch)]
#![feature(generic_param_attrs)]
#![cfg_attr(test, feature(test))]

#![allow(deprecated)]

extern crate alloc;

use std::cell::{Cell, RefCell};
use std::cmp;
use std::intrinsics;
use std::marker::{PhantomData, Send};
use std::mem;
use std::ptr;
use std::slice;

use alloc::raw_vec::RawVec;

/// An arena that can hold objects of only one type.
pub struct TypedArena<T> {
    /// A pointer to the next object to be allocated.
    ptr: Cell<*mut T>,

    /// A pointer to the end of the allocated area. When this pointer is
    /// reached, a new chunk is allocated.
    end: Cell<*mut T>,

    /// A vector of arena chunks.
    chunks: RefCell<Vec<TypedArenaChunk<T>>>,

    /// Marker indicating that dropping the arena causes its owned
    /// instances of `T` to be dropped.
    _own: PhantomData<T>,
}

struct TypedArenaChunk<T> {
    /// The raw storage for the arena chunk.
    storage: RawVec<T>,
}

impl<T> TypedArenaChunk<T> {
    #[inline]
    unsafe fn new(capacity: usize) -> TypedArenaChunk<T> {
        TypedArenaChunk {
            storage: RawVec::with_capacity(capacity),
        }
    }

    /// Destroys this arena chunk.
    #[inline]
    unsafe fn destroy(&mut self, len: usize) {
        // The branch on needs_drop() is an -O1 performance optimization.
        // Without the branch, dropping TypedArena<u8> takes linear time.
        if mem::needs_drop::<T>() {
            let mut start = self.start();
            // Destroy all allocated objects.
            for _ in 0..len {
                ptr::drop_in_place(start);
                start = start.offset(1);
            }
        }
    }

    // Returns a pointer to the first allocated object.
    #[inline]
    fn start(&self) -> *mut T {
        self.storage.ptr()
    }

    // Returns a pointer to the end of the allocated space.
    #[inline]
    fn end(&self) -> *mut T {
        unsafe {
            if mem::size_of::<T>() == 0 {
                // A pointer as large as possible for zero-sized elements.
                !0 as *mut T
            } else {
                self.start().offset(self.storage.cap() as isize)
            }
        }
    }
}

const PAGE: usize = 4096;

impl<T> TypedArena<T> {
    /// Creates a new `TypedArena`.
    #[inline]
    pub fn new() -> TypedArena<T> {
        TypedArena {
            // We set both `ptr` and `end` to 0 so that the first call to
            // alloc() will trigger a grow().
            ptr: Cell::new(0 as *mut T),
            end: Cell::new(0 as *mut T),
            chunks: RefCell::new(vec![]),
            _own: PhantomData,
        }
    }

    /// Allocates an object in the `TypedArena`, returning a reference to it.
    #[inline]
    pub fn alloc(&self, object: T) -> &mut T {
        if self.ptr == self.end {
            self.grow(1)
        }

        unsafe {
            if mem::size_of::<T>() == 0 {
                self.ptr
                    .set(intrinsics::arith_offset(self.ptr.get() as *mut u8, 1)
                        as *mut T);
                let ptr = mem::align_of::<T>() as *mut T;
                // Don't drop the object. This `write` is equivalent to `forget`.
                ptr::write(ptr, object);
                &mut *ptr
            } else {
                let ptr = self.ptr.get();
                // Advance the pointer.
                self.ptr.set(self.ptr.get().offset(1));
                // Write into uninitialized memory.
                ptr::write(ptr, object);
                &mut *ptr
            }
        }
    }
```

