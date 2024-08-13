<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class CheckDatabaseXSS extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'health:check-xss {--yes : Process all tables -y}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check script and xss bad data on database.';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        // get table list
        $tables = $this->getTableList();

        // on table list
        foreach ($tables as $key => $value) {
            if (!$this->option("yes")) {
                if ($this->ask("Do you want to proccessing `$value` table? (y|n)", 'y') == 'n') {
                    continue;
                }
            }

            // check record count
            if (DB::table($value)->count() == 0) {
                continue;
            }

            // print table name
            $this->info($value);

            $table = $value;
            $offset = 0;
            $limit = 2000;

            // on data with limit
            while (true) {
                $data = DB::table($table)
                    ->skip($offset)
                    ->take($limit)
                    ->get();

                // if array empty
                if (count($data) == 0) {
                    break;
                }

                // on data records
                $hasProblem = false;
                foreach ($data as $d_key => $d_value) {
                    // on data fields
                    foreach ($d_value as $df_key => $df_value) {
                        if ($this->containsXSSPatterns($df_value)) {
                            $hasProblem = true;
                            $this->warn($df_key . "=>" . $df_value);
                        }
                    }

                    // has problem
                    if ($hasProblem) {
                        if (property_exists($d_value, 'id')) {
                            $this->error("[id] : " . $d_value->id);
                        } else {
                            print_r($d_value);
                        }
                        $this->newLine();
                    }
                }

                // increase limit
                $offset += $limit;
            }
        }

        // print checked database
        $this->newLine();
        $this->newLine();
        $this->info("Process Success!");
        $this->line("Tables [" . count($tables) . "]: ");
        foreach ($tables as $value) {
            $this->line("-" . $value);
        }
    }

    public function getTableList(): array
    {
        $tables_obj = DB::select("show tables");

        $tables = [];
        foreach ($tables_obj as $key => $value) {
            $tables[] = $tables_obj[$key]->{"Tables_in_" . env("DB_DATABASE")};
        }

        return $tables;
    }

    public function containsXSSPatterns($input)
    {
        // Define an array of patterns to check for
        $patterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/<iframe\b[^>]*>(.*?)<\/iframe>/is',
            '/<object\b[^>]*>/is',
            '/<embed\b[^>]*>/is',
            '/<form\b[^>]*>/is',
            '/<input\b[^>]*>/is',
            '/<textarea\b[^>]*>/is',
        ];

        // Check each pattern against the input
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true; // Return true if any pattern matches
            }
        }

        return false; // Return false if no patterns match
    }
}
