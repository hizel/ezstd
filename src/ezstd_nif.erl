%% @private
-module(ezstd_nif).

-define(NOT_LOADED, not_loaded(?LINE)).

-on_load(load_nif/0).

-export([
    compress/2,
    decompress/1,
    create_cdict/2,
    create_ddict/1,
    compress_using_cdict/2,
    decompress_using_ddict/2,
    get_dict_id_from_cdict/1,
    get_dict_id_from_ddict/1,
    get_dict_id_from_frame/1
]).

%% nif functions

load_nif() ->
    SoName = get_priv_path(?MODULE),
    logger:debug(<<"Loading library: ~p ~n">>, [SoName]),
    ok = erlang:load_nif(SoName, 0).

get_priv_path(File) ->
    case code:priv_dir(ezstd) of
        {error, bad_name} ->
            Ebin = filename:dirname(code:which(?MODULE)),
            filename:join([filename:dirname(Ebin), "priv", File]);
        Dir ->
            filename:join(Dir, File)
    end.

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

compress(_Binary, _CompressionLevel) ->
    ?NOT_LOADED.

decompress(_Binary) ->
    ?NOT_LOADED.

create_cdict(_Binary, _CompressionLevel) ->
    ?NOT_LOADED.

create_ddict(_Binary) ->
    ?NOT_LOADED.

compress_using_cdict(_Binary, _CCDict) ->
    ?NOT_LOADED.

decompress_using_ddict(_Binary, _DDict) ->
    ?NOT_LOADED.

get_dict_id_from_cdict(_CDict) ->
    ?NOT_LOADED.

get_dict_id_from_ddict(_DDict) ->
    ?NOT_LOADED.

get_dict_id_from_frame(_Binary) ->
    ?NOT_LOADED.
