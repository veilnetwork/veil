# One answer to "may this build continue without the prebuilt media engine?",
# shared by linux/ and windows/ so the two platforms cannot drift into
# disagreeing about it. Included by both plugin CMakeLists.
#
# WHY THIS IS A DECISION AND NOT A CONSTANT
#
# The engine (libveil_media.so / veil_media.dll) is a gitignored prebuilt: a
# from-source WebRTC plus the veil engine/shim, tens of GB of checkout and
# hours of build. A clean clone never has one. Until now both files answered
# "no" with FATAL_ERROR, which meant a clean checkout could not START a linux
# or windows build — not "built without calls", could not build at all.
#
# That is the wrong answer for the person who just cloned the repo, and it is
# out of step with how this project already treats its other two optional
# natives: builder.py marks the whisper and translate steps optional, and the
# app reports those features as unavailable instead of offering something that
# cannot work.
#
# It is the RIGHT answer for a release. v0.9.1 shipped an APK with no engine;
# it installed, looked healthy, and threw at the first voice message. Voice
# messages, video notes, in-chat video, 1:1 and group calls and speech-to-text
# all load this library.
#
# So the strictness is conditional rather than absent.
#
# HOW THE DEFAULT STAYS SAFE
#
# Nobody has to know a flag exists to build locally, and no release can reach
# the permissive path by forgetting one, because the two paths are told apart
# by something a release intrinsically HAS rather than by something it must
# remember to pass:
#
#   1. -DVEIL_MEDIA_REQUIRE_ENGINE=ON|OFF     explicit, wins over everything
#   2. env VEIL_MEDIA_REQUIRE_ENGINE=1|0      how builder.py says "this is a
#                                             release" (flutter build linux /
#                                             windows drives cmake itself and
#                                             forwards no -D, so an env var is
#                                             the only channel there is)
#   3. env CI is set                          every CI runner sets it, and no
#                                             developer shell does. A release
#                                             job that forgets step 2 still
#                                             gets the strict path.
#   4. otherwise                              permissive: warn loudly, build
#                                             an app that says calls are
#                                             unavailable.
#
# Only 4 is reachable without a flag, and only off a CI runner. Forgetting
# something lands you in 3, which is strict. Reaching 4 from a release job
# takes writing VEIL_MEDIA_REQUIRE_ENGINE=0 on purpose.
#
# And this is not the only gate. It is the cheapest one, not the one that must
# hold: builder.py checks the produced bundle for the engine on a release, and
# release.yml greps the bundle again after that. Both are artifact checks —
# they cannot be satisfied by a flag.

# Resolve the policy. Sets ${out_required} to TRUE/FALSE and ${out_reason} to a
# human-readable account of which rule decided, for the message either branch
# then prints.
function(veil_media_engine_policy out_required out_reason)
  if(DEFINED VEIL_MEDIA_REQUIRE_ENGINE)
    if(VEIL_MEDIA_REQUIRE_ENGINE)
      set(${out_required} TRUE PARENT_SCOPE)
    else()
      set(${out_required} FALSE PARENT_SCOPE)
    endif()
    set(${out_reason} "VEIL_MEDIA_REQUIRE_ENGINE=${VEIL_MEDIA_REQUIRE_ENGINE} was passed to cmake" PARENT_SCOPE)
    return()
  endif()

  set(_env_req "$ENV{VEIL_MEDIA_REQUIRE_ENGINE}")
  if(NOT _env_req STREQUAL "")
    # if(<string>) applies CMake's own truthiness, so 0/OFF/NO/FALSE are false
    # and 1/ON/YES/TRUE are true. Spelling it any of those ways works.
    if(_env_req)
      set(${out_required} TRUE PARENT_SCOPE)
    else()
      set(${out_required} FALSE PARENT_SCOPE)
    endif()
    set(${out_reason} "VEIL_MEDIA_REQUIRE_ENGINE=${_env_req} is set in the environment" PARENT_SCOPE)
    return()
  endif()

  set(_env_ci "$ENV{CI}")
  if(_env_ci)
    set(${out_required} TRUE PARENT_SCOPE)
    set(${out_reason} "CI=${_env_ci} — an automated build is assumed to be shipping something" PARENT_SCOPE)
    return()
  endif()

  set(${out_required} FALSE PARENT_SCOPE)
  set(${out_reason} "this is a local build (no VEIL_MEDIA_REQUIRE_ENGINE, no CI)" PARENT_SCOPE)
endfunction()

# The shared half of what each platform says when its engine is missing: the
# same list of dead features and the same account of who decides.
#
# how_to_build is ONE argument. It is checked, because the first version of
# this was called with the recipe split across three quoted strings — CMake put
# the last two in ARGN and the warning shipped truncated mid-sentence. A
# warning nobody can act on is worse than the absent build it describes.
function(veil_media_engine_absent_warning engine_path platform how_to_build)
  if(ARGC GREATER 3)
    message(FATAL_ERROR
      "veil_media_engine_absent_warning takes exactly 3 arguments, got ${ARGC}. "
      "The extra ones would be dropped and the recipe would print truncated. "
      "Pass the whole recipe as a single quoted string.")
  endif()
  message(WARNING
    "veil_media (${platform}): building WITHOUT the call media engine.\n"
    "  missing: ${engine_path}\n"
    "  This build will run. Calls, group calls, voice messages, video notes and\n"
    "  speech-to-text will report themselves as unavailable rather than working —\n"
    "  the Dart side checks the engine is loadable before it offers them.\n"
    "  To get those features, put the prebuilt engine at the path above:\n"
    "${how_to_build}"
    "  A release refuses instead of warning; VEIL_MEDIA_REQUIRE_ENGINE / CI decide\n"
    "  which you get — see cmake/veil_media_engine_policy.cmake.")
endfunction()
