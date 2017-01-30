/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <tuple>

template<class ... Args>
class Pipe {
    using Tuple = std::tuple<std::decay_t<Args>...>;
public:
    template<class... As>
    void apply(As&&... args) {
        if (_queued_funcs.empty()) {
            _queued_args.emplace(std::forward<As>(args)...);
            return;
        }
        auto h = std::move(_queued_funcs.front());
        _queued_funcs.pop();
        h(std::forward<As>(args)...);
    }

    template<class... As>
    void post_apply(boost::asio::io_service& ios, As&&... args) {
        if (_queued_funcs.empty()) {
            _queued_args.emplace(std::forward<As>(args)...);
            return;
        }
        auto h = std::move(_queued_funcs.front());
        _queued_funcs.pop();

        auto args_tuple = std::make_shared<Tuple>(std::forward<As>(args)...);

        ios.post([args_tuple, h = std::move(h)] {
                apply_f(std::move(h), std::move(*args_tuple));
            });
    }

    template<class H>
    void schedule(boost::asio::io_service& ios, H&& h) {
        if (_queued_args.empty()) {
            _queued_funcs.push(std::forward<H>(h));
            return;
        }

        auto args = std::make_shared<Tuple>(std::move(_queued_args.front()));
        _queued_args.pop();
        ios.post([args = std::move(args), h = std::forward<H>(h)] {
                apply_f(std::move(h), std::move(*args));
            });
    }

    void clear() {
        _queued_args  = decltype(_queued_args)();
        _queued_funcs = decltype(_queued_funcs)();
    }

private:
    template <class F, class Tuple, size_t... Is>
    static
    constexpr auto apply_impl(F&& f, Tuple&& t,
                              std::index_sequence<Is...>) {
        return std::forward<F>(f)(std::get<Is>(std::forward<Tuple>(t))...);
    }
    
    template <class F, class Tuple>
    static
    constexpr auto apply_f(F&& f, Tuple&& t) {
        using namespace std;

        return apply_impl(
            forward<F>(f),
            forward<Tuple>(t),
            make_index_sequence<tuple_size<decay_t<Tuple>>{}>{});
    }

private:
    std::queue<std::tuple<std::decay_t<Args>...>> _queued_args;
    std::queue<std::function<void(Args...)>> _queued_funcs;
};

