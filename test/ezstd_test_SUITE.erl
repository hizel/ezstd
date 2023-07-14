-module(ezstd_test_SUITE).

-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() -> [
    roundtrip_content_dictionary_test,
    roundtrip_content_using_real_dictionary_test,
    roundtrip_normal_compression_test,
    streaming_test1,
    streaming_test2,
    storage_test
].

roundtrip_normal_compression_test(_) ->
  Plaintext = <<"contentcontentcontentcontent">>,
  Compressed = ezstd:compress(Plaintext, 1),
  ?assertEqual(Plaintext, ezstd:decompress(Compressed)).

roundtrip_content_dictionary_test(_) ->
  Dict = <<"content-dict">>,
  CDict = ezstd:create_cdict(Dict, 1),
  DDict = ezstd:create_ddict(Dict),
  Plaintext = <<"contentcontentcontentcontent">>,

  ContentCompressed = ezstd:compress_using_cdict(Plaintext, CDict),
  ?assertEqual(Plaintext, ezstd:decompress_using_ddict(ContentCompressed, DDict)).

roundtrip_content_using_real_dictionary_test(_) ->
  Dict = real_dictionary(),
  CDict = ezstd:create_cdict(Dict, 1),

  ?assertEqual(967448963, ezstd:get_dict_id_from_cdict(CDict)),

  DDict = ezstd:create_ddict(Dict),

  ?assertEqual(967448963, ezstd:get_dict_id_from_ddict(DDict)),
  Plaintext = <<"contentcontentcontentcontent">>,

  DictCompressed = ezstd:compress_using_cdict(Plaintext, CDict),
  ?assertEqual(967448963, ezstd:get_dict_id_from_frame(DictCompressed)),
  ?assertEqual(Plaintext, ezstd:decompress_using_ddict(DictCompressed, DDict)).

% internals

real_dictionary() ->
  <<16#37,16#a4,16#30,16#ec,16#83,16#19,16#aa,16#39,16#9,16#10,16#10,16#df,16#30,16#33,16#33,16#b3,16#77,16#a,16#33,16#f1,16#78,16#3c,16#1e,16#8f,16#c7,16#e3,16#f1,16#78,16#3c,16#cf,16#f3,16#bc,16#f7,16#d4,16#42,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#41,16#a1,16#50,16#28,16#14,16#a,16#85,16#42,16#a1,16#50,16#28,16#14,16#a,16#85,16#a2,16#28,16#8a,16#a2,16#28,16#4a,16#29,16#7d,16#74,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#e1,16#f1,16#78,16#3c,16#1e,16#8f,16#c7,16#e3,16#f1,16#78,16#9e,16#e7,16#79,16#ef,16#1,16#1,16#0,16#0,16#0,16#4,16#0,16#0,16#0,16#8,16#0,16#0,16#0,16#63,16#6f,16#6e,16#74,16#65,16#6e,16#74,16#a>>.


streaming_test1(_) ->
  streaming_test0(128_000, random),
  streaming_test0(128_000, <<"hi">>),
  streaming_test0(128_000, <<"1234567890">>).

streaming_test2(_) ->
  streaming_test0(1_000_000, random),
  streaming_test0(1_000_000, <<"hi">>),
  streaming_test0(1_000_000, <<"1234567890">>).

streaming_test0(Len, Pattern) ->
  {ok, Ctx} = ezstd:create_compress_stream(0),

  {InList, OutList} = lists:foldl(fun(_, {InAcc, OutAcc}) ->
      Bin = case Pattern of 
        random -> crypto:strong_rand_bytes(Len);
        _ -> binary:copy(Pattern, Len div byte_size(Pattern))
      end, 
      OutBin = ezstd:compress_stream(Ctx, Bin),
      {[Bin|InAcc], [OutBin|OutAcc]}
  end, {[], []}, lists:seq(1, 10)),

  Compress = iolist_to_binary(lists:reverse([ezstd:compress_stream(Ctx, flush)|OutList])),
  Input = iolist_to_binary(lists:reverse(InList)),

  {error, _} = ezstd:decompress(Compress),

  Input = ezstd:decompress_stream_onepass(Compress),

  ok.

  storage_test(_) ->
  {ok, Ctx} = ezstd:create_compressed_storage(1, 1_000_000),

  InList = lists:foldl(fun(_, InAcc) ->
    Bin = crypto:strong_rand_bytes(100_000),
    {ok, _} = ezstd:compress_to_storage(Ctx, Bin),
    [Bin|InAcc]
  end, [], lists:seq(1, 20)),

  Input = iolist_to_binary(lists:reverse(InList)),

  {ok, Compress} = ezstd:flush_compressed_storage(Ctx),

  Input = ezstd:decompress_stream_onepass(Compress),

  ok.
