<?php

namespace Collective\Remote;

use phpseclib3\Net\SFTP;
use phpseclib3\Net\SSH2;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use phpseclib3\System\SSH\Agent;
use Illuminate\Filesystem\Filesystem;
use phpseclib3\Crypt\PublicKeyLoader;

class SecLibGateway implements GatewayInterface
{
    protected $host;
    protected $port = 22;
    protected $timeout = 10;
    protected $auth;
    protected $files;
    protected $connection;

    public function __construct($host, array $auth, Filesystem $files, $timeout)
    {
        $this->auth = $auth;
        $this->files = $files;
        $this->setTimeout($timeout);
        $this->setHostAndPort($host);
    }

    protected function setHostAndPort($host)
    {
        $host = Str::replaceFirst('[', '', $host);
        $host = Str::replaceLast(']', '', $host);
        $this->host = $host;

        if (!filter_var($host, FILTER_VALIDATE_IP) && Str::contains($host, ':')) {
            $this->host = Str::beforeLast($host, ':');
            $this->port = (int) Str::afterLast($host, ':');
        }

        if (filter_var($this->host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $this->host = '[' . $this->host . ']';
        }
    }

    public function connect($username)
    {
        return $this->getConnection()->login($username, $this->getAuthForLogin());
    }

    public function getConnection()
    {
        return $this->connection ?: $this->connection = new SFTP($this->host, $this->port, $this->timeout);
    }

    protected function getAuthForLogin()
    {
        if ($this->useAgent()) {
            return $this->getAgent();
        } elseif ($this->hasRsaKey()) {
            return $this->loadRsaKey($this->auth);
        } elseif (isset($this->auth['password'])) {
            return $this->auth['password'];
        }

        throw new \InvalidArgumentException('Password / key is required.');
    }

    protected function useAgent()
    {
        return isset($this->auth['agent']) && $this->auth['agent'] === true;
    }

    public function getAgent()
    {
        return new Agent();
    }

    protected function hasRsaKey()
    {
        return !empty(trim($this->auth['key'] ?? '')) || !empty(trim($this->auth['keytext'] ?? ''));
    }

    protected function loadRsaKey(array $auth)
    {
        return PublicKeyLoader::load($this->readRsaKey($auth), Arr::get($auth, 'keyphrase'));
    }

    protected function readRsaKey(array $auth)
    {
        return isset($auth['key']) ? $this->files->get($auth['key']) : $auth['keytext'];
    }

    public function setTimeout($timeout)
    {
        $this->timeout = (int) $timeout;
        if ($this->connection) {
            $this->connection->setTimeout($this->timeout ?: 10);
        }
    }

    public function connected()
    {
        return $this->getConnection()->isConnected();
    }

    public function run($command)
    {
        $this->getConnection()->exec($command, false);
    }

    public function get($remote, $local)
    {
        $this->getConnection()->get($remote, $local);
    }

    public function getString($remote)
    {
        $content = $this->getConnection()->get($remote);
        return $content !== false ? $content : '';
    }

    public function put($local, $remote)
    {
        $this->getConnection()->put($remote, $local, SFTP::SOURCE_LOCAL_FILE);
    }

    public function putString($remote, $contents)
    {
        $this->getConnection()->put($remote, $contents);
    }

    public function exists($remote)
    {
        return $this->getConnection()->is_file($remote);
    }

    public function rename($remote, $newRemote)
    {
        return $this->getConnection()->rename($remote, $newRemote);
    }

    public function delete($remote)
    {
        return $this->getConnection()->delete($remote);
    }

    public function nextLine()
    {
        $line = $this->getConnection()->read();
        return $line !== false ? $line : null;
    }

    public function status()
    {
        return $this->getConnection()->getExitStatus();
    }

    public function getHost()
    {
        return $this->host;
    }

    public function getPort()
    {
        return $this->port;
    }
}

