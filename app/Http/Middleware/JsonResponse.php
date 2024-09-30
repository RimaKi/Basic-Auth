<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class JsonResponse
{
    /**
     *  Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @return \Illuminate\Http\JsonResponse|mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $result = $next($request);
        if ($result->exception == null) {
            $data = $result->getOriginalContent();
            $message = "trans.method." . $request->getMethod() . ".success";
            $success = true;
            $status = 200;
            if (gettype($result->getOriginalContent()) == 'array') {
                if (array_key_exists('message', $data)) {
                    $message = $data['message'];
                }
                if (array_key_exists("success", $data)) {
                    $success = $data["success"];
                }
                if (array_key_exists("status", $data)) {
                    $status = $data["status"];
                }
                $data = collect($result->getOriginalContent())->except(['message', 'success', 'status']);
            } elseif (gettype($result->getOriginalContent()) == 'string') {
                $message = $result->getOriginalContent();
                $data = null;
            }
            $result = response()->json([
                "success" => $success,
                "data" => $data,
                "message" => $message
            ], $status);
        }
        return $result;
    }
}
