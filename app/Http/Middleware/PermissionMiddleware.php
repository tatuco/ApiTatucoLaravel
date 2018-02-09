<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Support\Facades\Auth;
use DB;
use Tymon\JWTAuth\Facades\JWTAuth;

class PermissionMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, $permissions)
    {
       echo $user = JWTAuth::parseToken()->authenticate();

        $roles = DB::table('roles as r')
            ->join('role_user as ru','r.id','=','ru.role_id')
            ->select('r.slug')
            ->where('ru.user_id','=',1)->get();
        $user = User::find(1);

        echo "query".$roles;
       echo $user = User::find(1)->roles();
        if ($user) {
            if (!$user->user()->can($permissions)) {
                if ($request->ajax()) {
                    return response('Unauthorized.', 403);
                }

                abort(403, 'Unauthorized action.');
            }
        } else {
            $guest = Role::whereSlug('guest')->first();

            if ($guest) {
                if (!$guest->can($permissions)) {
                    if ($request->ajax()) {
                        return response('Unauthorized.', 403);
                    }

                    abort(403, 'Unauthorized action.');
                }
            }
        }

    }
}
